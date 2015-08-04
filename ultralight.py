#!/usr/bin/env python3
#
# A Python implementation for Mifare Ultralight cards.
#
# Copyright (c) 2015, Alexandre Hamelin <alexandre.hamelin gmail.com>
#
# This work is distributed under the LGPL license. See LICENSE.txt for details.


import sys
import os


class MFUCard:
    def __init__(self, *, bytes=None, file=None, hexfile=None):
        import builtins

        if [bytes, file, hexfile].count(None) < 2:
            raise RuntimeError('only one of bytes, file or hexfile must be specified')

        if bytes is not None:
            if not isinstance(bytes, (builtins.bytes, bytearray)):
                raise TypeError('invalid bytes parameter')
            elif len(bytes) != 64:
                raise ValueError('byte array must be 64 bytes long')
            self._bytes = builtins.bytes(bytes)
        elif file is not None:
            # file can be any of a file object, a filename or a file descriptor
            self._bytes = self._load(file, 'rb')
        elif hexfile is not None:
            # hexfile can be any of a file object, a filename or a file
            # descriptor
            content = self._load(hexfile, 'r', 1024)
            content = content.replace(b'\r', b'').replace(b'\n', b'').replace(b' ', b'').replace(b'\t', b'')
            self._bytes = builtins.bytes(bytearray.fromhex(content.decode()))
        else:
            self._bytes = builtins.bytes(64)

        assert type(self._bytes) is builtins.bytes
        assert len(self._bytes) == 64

        self._page_view_proxy = None


    def _load(self, file, mode, count=64):
        orig_file = None
        if isinstance(file, str):
            file = open(file, mode)
            orig_file = file
        if hasattr(file, 'fileno'):
            file = file.fileno()
        content = os.read(file, count)
        if orig_file:
            orig_file.close()
        return content

    def __iter__(self):
        return iter(self._bytes)

    def __len__(self):
        return len(self._bytes)

    def hexdump(self, file=sys.stdout):
        for page in self.pages:
            print('{:08x}'.format(int.from_bytes(page, 'big')), file=file)

    def dump(self, file):
        if isinstance(file, str):
            with open(file, 'w') as fp:
                fp.write(self._bytes)
        elif hasattr(file, 'write'):
            file.write(self._bytes)
        else:
            raise TypeError('invalid output file')

    @property
    def pages(self):
        if self._page_view_proxy is None:
            self._page_view_proxy = MFUPageViewProxy(self)
        return self._page_view_proxy

    def __getitem__(self, index):
        if isinstance(index, (int, slice)):
            return self._bytes[index]
        else:
            raise TypeError('invalid index: {}'.format(index))

    @property
    def id(self):
        # 7-byte UID, excludes the two check bytes
        # MF0ICU1, section 7.5.1
        return int.from_bytes(self._bytes[:3] + self._bytes[4:8], 'big')

    @property
    def manufacturer(self):
        return self._bytes[0]

    @property
    def bcc0(self):
        return self._bytes[3]

    @property
    def bcc1(self):
        return self._bytes[8]

    @property
    def id0(self):
        return self._bytes[0]

    @property
    def id1(self):
        return self._bytes[1]

    @property
    def id2(self):
        return self._bytes[2]

    @property
    def id3(self):
        return self._bytes[4]

    @property
    def id4(self):
        return self._bytes[5]

    @property
    def id5(self):
        return self._bytes[6]

    @property
    def id6(self):
        return self._bytes[7]

    @property
    def serial(self):
        # same as UID, ref: MF0ICU1.pdf, section 7.5.1
        return self.id

    @property
    def internal(self):
        return self._bytes[9]

    @property
    def lockbytes(self):
        return self._bytes[10:12]

    def is_readonly(self, index):
        if index == 0 or index == 1:
            return True
        elif index == 2 or index == 3:
            return False
        else:
            pass


class MFUPage:
    # A page is just an indexed view in a card.

    def __init__(self, card, index):
        if not isinstance(card, MFUCard):
            raise TypeError('invalid card object')
        elif 0 <= index < 16:
            self._card = card
            self._index = index
        else:
            raise ValueError('invalid index {}'.format(index))

    def __len__(self):
        return 4

    def __str__(self):
        pagebytes = self._i2p()
        return 'Page {}: {} {} {} {}'.format(self._index, *pagebytes)

    def __getitem__(self, index):
        if isinstance(index, (int, slice)):
            pagebytes = self._i2p()
            return pagebytes[index]
        else:
            raise TypeError('invalid index: {}'.format(index))

    def __iter__(self):
        pagebytes = self._i2p()
        return iter(pagebytes)

    def _i2p(self):
        """Index to page"""
        pagebytes = self._card[self._index*4:self._index*4+4]
        return pagebytes

    def to_int(self):
        return int.from_bytes(self._i2p(), 'big')

    def to_hex(self):
        return ''.join('{:02x}'.format(b) for b in self._i2p())

    @property
    def readonly(self):
        if self._index in (0, 1):
            return True
        else:
            locked_bits = int.from_bytes(self._card.lockbytes, 'little')
            # page 2 is read-only only when the block-locking bits are all set
            if self._index == 2:
                return locked_bits & 0x0007 == 0x0007
            elif self._index == 3:
                return locked_bits & 0x0008 != 0
            else:
                return (1 << self._index) & locked_bits != 0


class MFUPageViewProxy:
    def __init__(self, card):
        self._card = card
        self._pages = [MFUPage(self._card, i) for i in range(16)]

    def __getitem__(self, index):
        return self._pages[index]

        def slice2range(s):
            start = s.start if s.start is not None else 0
            stop = s.stop if s.stop is not None else len(self)
            step = s.step if s.step is not None else 1
            return range(start, stop, step)

        if isinstance(index, int):
            if index < 0:
                index += len(self)
            if index < 0 or index >= len(self):
                raise IndexError('invalid page index')
            page = MFUPage(self._card, index)
            return page
        elif isinstance(index, slice):
            pages = [MFUPage(self._card, i) for i in slice2range(index)]
            return pages
        else:
            raise TypeError('invalid page index')

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            raise NotImplementedError('pages do not support slice assignments')
        if not isinstance(index, int):
            raise TypeError('invalid index type {}'.format(type(index)))
        if index >= len(self):
            raise IndexError('invalid page index {}'.format(index))

        def set_bytes(fourbytes):
            self._card._bytes = (self._card._bytes[:index*4] +
                                 fourbytes +
                                 self._card._bytes[index*4+4:])

        if isinstance(value, int):
            set_bytes(value.to_bytes(4, 'big'))
        elif isinstance(value, (bytes, bytearray)):
            if len(value) != 4:
                raise ValueError('byte assignments must be 4 bytes')
            set_bytes(bytes(value))
        elif isinstance(value, str):
            set_bytes(value.encode('latin-1'))
        else:
            raise ValueError('value must be a 4-byte string, int or byte array')

    def __iter__(self):
        return iter(self._pages)

    def __len__(self):
        return 16


