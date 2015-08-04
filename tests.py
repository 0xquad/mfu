#!/usr/bin/env python3
#
# The test program for the MFU Python library.
#
# Copyright (c) 2015, Alexandre Hamelin <alexandre.hamelin gmail.com>
#
# This work is distributed under the LGPL license. See LICENSE.txt for details.



import sys
import unittest
from unittest.mock import Mock, call, patch, ANY

from ultralight import MFUCard, MFUPage, MFUPageViewProxy



class MFUTests(unittest.TestCase):
    def __init__(self, *args):
        super().__init__(*args)
        content = (
            '04AD7150'
            'FADA2E80'
            '8E48E000'
            '00000000'
            '00000000'
            '31880220'
            '633C0000'
            'E92D2412'
            '00000000'
            '00000000'
            '00013634'
            '0000907B'
            '00000000'
            '00000000'
            '00000000'
            '00000000'
        )
        content = bytearray.fromhex(content)
        self.card = MFUCard(bytes=content)


    def test_iter_bytes(self):
        iterator = iter(self.card)
        firstbytes = [next(iterator) for i in range(4)]
        self.assertEqual(firstbytes, [0x04, 0xad, 0x71, 0x50])
        for i in range(len(self.card) - 4):
            next(iterator)
        with self.assertRaises(StopIteration):
            next(iterator)


    def test_length(self):
        self.assertEqual(len(self.card), 64)


    def test_hexdump(self):
        output = []
        def myprint(data, *args, **kwargs):
            output.append(str(data))
            output.append('\n')

        mock_print = Mock(side_effect=myprint)
        # patching sys.stdout doesn't work since the function already has
        # a reference to the real sys.stdout at define time
        with patch('builtins.print', mock_print):
            self.card.hexdump()
        expected = (
            '04ad7150\n'
            'fada2e80\n'
            '8e48e000\n'
            '00000000\n'
            '00000000\n'
            '31880220\n'
            '633c0000\n'
            'e92d2412\n'
            '00000000\n'
            '00000000\n'
            '00013634\n'
            '0000907b\n'
            '00000000\n'
            '00000000\n'
            '00000000\n'
            '00000000\n'
        )
        self.assertEqual(''.join(output), expected)


    def test_hexdump_with_custom_output(self):
        output = []
        def write(data):
            output.append(data)

        filemock = Mock()
        filemock.write.side_effect = write
        self.card.hexdump(file=filemock)
        expected = (
            '04ad7150\n'
            'fada2e80\n'
            '8e48e000\n'
            '00000000\n'
            '00000000\n'
            '31880220\n'
            '633c0000\n'
            'e92d2412\n'
            '00000000\n'
            '00000000\n'
            '00013634\n'
            '0000907b\n'
            '00000000\n'
            '00000000\n'
            '00000000\n'
            '00000000\n'
        )
        self.assertEqual(''.join(output), expected)


    def test_dump(self):
        output = []
        def write(data):
            output.append(data)

        filemock = Mock(sys.stdout)
        filemock.write.side_effect = write
        self.card.dump(filemock)
        expected = (
            b'\x04\xad\x71\x50'
            b'\xfa\xda\x2e\x80'
            b'\x8e\x48\xe0\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x31\x88\x02\x20'
            b'\x63\x3c\x00\x00'
            b'\xe9\x2d\x24\x12'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x01\x36\x34'
            b'\x00\x00\x90\x7b'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
        )
        self.assertEqual(b''.join(output), expected)


    def test_page_view_is_singleton(self):
        view1 = self.card.pages
        view2 = self.card.pages
        self.assertIs(view1, view2)


    def test_get_byte_by_index(self):
        self.assertEqual(self.card[0], 4)
        self.assertEqual(self.card[4], 0xfa)
        self.assertEqual(self.card[8], 0x8e)
        self.assertEqual(self.card[47], 0x7b)

        self.assertEqual(self.card[-1], 0)
        self.assertEqual(self.card[-len(self.card)], 4)


    def test_get_bytes_by_slice(self):
        data = self.card[:4]
        self.assertEqual(data, b'\x04\xad\x71\x50')
        data = self.card[10:12]
        self.assertEqual(data, b'\xe0\x00')
        data = self.card[60:]
        self.assertEqual(data, b'\x00\x00\x00\x00')


    def test_get_bytes_by_invalid_index(self):
        for i in (str, dict, list, tuple, set, bytes, bytearray,
                  complex, lambda: None, object()):
            with self.assertRaises(TypeError):
                self.card[i]
        with self.assertRaises(IndexError):
            self.card[-len(self.card)-1]
        with self.assertRaises(IndexError):
            self.card[len(self.card)]


    def test_get_page(self):
        self.assertEqual(bytes(self.card.pages[0]), b'\x04\xAD\x71\x50')


    def test_byte_by_getitem(self):
        self.assertEqual(self.card[0], 0x04)


    def test_bytes_by_slice(self):
        self.assertEqual(self.card[:2], b'\x04\xAD')


    def test_basic_attributes(self):
        self.assertEqual(self.card.id, 0x04ad71fada2e80)
        self.assertEqual(self.card.manufacturer, 0x04)
        self.assertEqual(self.card.bcc0, 0x50)
        self.assertEqual(self.card.bcc1, 0x8e)
        self.assertEqual(self.card.id0, 0x04)
        self.assertEqual(self.card.id1, 0xad)
        self.assertEqual(self.card.id2, 0x71)
        self.assertEqual(self.card.id3, 0xfa)
        self.assertEqual(self.card.id4, 0xda)
        self.assertEqual(self.card.id5, 0x2e)
        self.assertEqual(self.card.id6, 0x80)


    def test_first_pages_are_readonly(self):
        for p in [0, 1]:
            self.assertTrue(self.card.pages[p].readonly)


    def test_locked_pages_are_read_only(self):
        self.skipTest('not implemented')
        #self.assertTrue(card.otp_locked)
        #self.assertTrue(card.pages4to9_blocked)
        #self.assertFalse(card.pages10to15_blocked)
        #self.assertFalse(card.otp_blocked)


    def test_init_default_empty(self):
        # initialized to all zeroes
        card = MFUCard()
        self.assertEqual(bytes(card), b'\x00' * 64)


    def test_init_one_param_only(self):
        with self.assertRaises(RuntimeError):
            mfu = MFUCard(bytes=b'abcd'*4, file=1)
        with self.assertRaises(RuntimeError):
            mfu = MFUCard(bytes=b'abcd'*4, hexfile=1)
        with self.assertRaises(RuntimeError):
            mfu = MFUCard(file=1, hexfile=1)
        with self.assertRaises(RuntimeError):
            mfu = MFUCard(bytes=b'abcd'*4, file=1, hexfile=1)


    def test_init_bytestring(self):
        # initialized with bytes, must be 64 bytes
        card = MFUCard(bytes=b'\x01' * 64)
        self.assertEqual(bytes(card), b'\x01' * 64)


    def test_init_bytes(self):
        card = MFUCard(bytes=bytes(64))
        self.assertEqual(bytes(card), b'\x00' * 64)
        card = MFUCard(bytes=bytearray([i for i in range(64)]))
        self.assertEqual(list(card), [i for i in range(64)])


    def test_init_from_file(self):
        # load from a 64-byte binary file
        content = b'\x01\x02\03\x04' * 16
        fp_mock = Mock(sys.stdin)
        fp_mock.fileno.return_value = 3
        with patch('builtins.open', return_value=fp_mock) as mock_open, \
             patch('os.read', return_value=content) as mock_sysread:
            card = MFUCard(file='card.bin')
            self.assertEqual(bytes(card), content)


    def test_init_from_file_descriptor(self):
        def sysread(desc, n):
            return b'\x01' * n

        with patch('os.read', wraps=sysread) as mock_sysread:
            card = MFUCard(file=3)
            mock_sysread.assert_called_with(3, ANY)
            self.assertEqual(bytes(card), b'\x01' * 64)


    def test_init_from_hexfile(self):
        # load from an ASCII hex file, spaces ignored, case-insensitive
        content = b'0badc0de' * 16
        fp_mock = Mock(sys.stdin)
        fp_mock.fileno.return_value = 3
        with patch('builtins.open', return_value=fp_mock) as mock_open, \
             patch('os.read', return_value=content) as mock_sysread:
            card = MFUCard(hexfile='card.txt')
            self.assertEqual(bytes(card), b'\x0b\xad\xc0\xde' * 16)


    def test_init_from_hexfile_file_descriptor(self):
        def sysread(desc, n):
            if not hasattr(sysread, 'filepos'):
                sysread.filepos = 0
            filedata = (
                b'00010203'
                b'01020304'
                b'02030405'
                b'03040506'
                b'04050607'
                b'05060708'
                b'06070809'
                b'0708090a'
                b'08090a0b'
                b'090a0b0c'
                b'0a0b0c0d'
                b'0b0c0d0e'
                b'0c0d0e0f'
                b'0d0e0f00'
                b'0e0f0001'
                b'0f000102'
            )
            chunk = filedata[sysread.filepos:sysread.filepos+n]
            sysread.filepos = min(sysread.filepos + n, len(filedata))
            return chunk

        with patch('os.read', wraps=sysread) as mock_sysread:
            card = MFUCard(hexfile=3)
            mock_sysread.assert_called_with(3, ANY)
            expected = b''.join(bytes([i, (i + 1) % 16,
                                          (i + 2) % 16,
                                          (i + 3) % 16])
                                for i in range(16))
            self.assertEqual(bytes(card), expected)



class MFUPageTests(unittest.TestCase):
    def __init__(self, name):
        super().__init__(name)
        card = MFUCard(bytes=bytes([1,2,3,4]*16))
        self.page = MFUPage(card, 0)


    def test_iter_bytes(self):
        byteiter = iter(self.page)
        b = next(byteiter)
        self.assertEqual(b, 1)
        b = next(byteiter)
        self.assertEqual(b, 2)
        b = next(byteiter)
        self.assertEqual(b, 3)
        b = next(byteiter)
        self.assertEqual(b, 4)
        with self.assertRaises(StopIteration):
            next(byteiter)


    def test_as_list(self):
        bytelist = list(self.page)
        self.assertIsInstance(bytelist, list)
        self.assertEqual(bytelist, [1, 2, 3, 4])


    def test_slice(self):
        self.assertEqual(self.page[0], 1)
        self.assertEqual(self.page[1:-1], b'\x02\x03')


    @unittest.skip('item assignment is not implemented')
    def test_set_bytes_types(self):
        self.assertNotEqual(self.page[0], 99)
        self.page[0] = 99
        self.assertEqual(self.page[0], 99)

        self.page[0] = b'\x99'
        self.assertEqual(self.page[0], 0x99)


    @unittest.skip('item assignment is not implemented')
    def test_set_bytes_negative_index(self):
        self.assertNotEqual(self.page[-1], 99)
        self.page[-1] = 99
        self.assertEqual(self.page[-1], 99)


    @unittest.skip('item assignment is not implemented')
    def test_set_bytes_slice_value_types(self):
        self.assertNotEqual(self.page[:2], b'\x88\x99')
        self.page[:2] = bytes([0x88, 0x99])
        self.assertEqual(self.page[:2], b'\x88\x99')

        self.page[:2] = bytes([0x10, 0x20])
        self.assertEqual(self.page[:2], b'\x10\x20')

        self.page[:2] = b'\x11\x21'
        self.assertEqual(self.page[:2], b'\x11\x21')

        self.page[:2] = [0x12, 0x22]
        self.assertEqual(self.page[:2], b'\x12\x22')

        class C:
            def __iter__(self):
                return next(self)
            def __next__(self):
                yield 0x13
                yield 0x23

        self.page[:2] = C()
        self.assertEqual(self.page[:2], b'\x13\x23')


    @unittest.skip('item assignment is not implemented')
    def test_set_bytes_invalid_value(self):
        for t in (str, complex, float, set, list, tuple, dict):
            with self.assertRaises(ValueError):
                self.page[0] = t()

        with self.assertRaises(ValueError):
            self.page[0] = 256
        with self.assertRaises(ValueError):
            self.page[0] = -1


    @unittest.skip('item assignment is not implemented')
    def test_set_bytes_invalid_index(self):
        for t in (str, complex, float, set, list, tuple, dict):
            with self.assertRaises(TypeError):
                self.page[t()] = 0

        with self.assertRaises(ValueError):
            self.page[5] = 0


    def test_invalid_index(self):
        for t in (str, list, set, dict, complex, object):
            with self.assertRaises(TypeError):
                self.page[t()]


    def test_to_hex(self):
        hexstr = self.page.to_hex()
        self.assertEqual(hexstr, '01020304')


    def test_to_int(self):
        value = self.page.to_int()
        self.assertEqual(value, 0x01020304)


    def test_length(self):
        self.assertEqual(len(self.page), 4)


    def test_init_invalid_page(self):
        card = MFUCard()
        with self.assertRaises(ValueError):
            MFUPage(card, -1)
        with self.assertRaises(ValueError):
            MFUPage(card, 16)


    def test_init_invalid_card(self):
        card = object()
        with self.assertRaises(TypeError):
            MFUPage(card, 0)


    def test_readonly(self):
        card = MFUCard()
        pages = [MFUPage(card, i) for i in range(16)]
        for p in (0, 1):
            self.assertTrue(pages[p].readonly)
        for p in range(2, 16):
            self.assertFalse(pages[p].readonly)

        card = MFUCard(bytes=
            b'\x00\x00\x00\x00' * 2 +
            # lock bytes value = 0x55aa
            # meaning:  pages 5, 7, 8, 10, 12, 14 are LOCKED
            #           pages 4, 6, 9, 11, 13, 15 are not locked
            #           otp locking protection is off
            #           pages 9-4 locking protection is ON
            #           pages 15-10 locking protection is off
            #           otp area is LOCKED
            b'\x00\x00\xaa\x55' +
            b'\x00\x00\x00\x00' * 13
        )
        pages = [MFUPage(card, i) for i in range(16)]
        for p in (0, 1):
            # readonly pages
            self.assertTrue(pages[p].readonly)
        for p in (5, 7, 8, 10, 12, 14):
            # locked pages
            self.assertTrue(pages[p].readonly)
        for p in (4, 6, 9, 11, 13, 15):
            # pages not locked
            self.assertFalse(pages[p].readonly)



class MFUPageViewProxyTests(unittest.TestCase):
    def __init__(self, name):
        super().__init__(name)
        self.card = MFUCard()


    def test_length(self):
        self.assertEqual(len(self.card.pages), 16)


    def test_pages_proxy(self):
        self.assertIsInstance(self.card.pages, MFUPageViewProxy)


    def test_page_by_index(self):
        self.assertIsInstance(self.card.pages[0], MFUPage)
        self.assertIs(self.card.pages[-1], self.card.pages[15])


    def test_pages_by_slice(self):
        pages = self.card.pages[:2]
        self.assertIsInstance(pages, list)
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(isinstance(p, MFUPage) for p in pages))

        pages = self.card.pages[10:]
        self.assertIsInstance(pages, list)
        self.assertEqual(len(pages), 6)
        self.assertTrue(all(isinstance(p, MFUPage) for p in pages))

        pages = self.card.pages[8:10]
        self.assertIsInstance(pages, list)
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(isinstance(p, MFUPage) for p in pages))

        pages = self.card.pages[10:8:-1]
        self.assertIsInstance(pages, list)
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(isinstance(p, MFUPage) for p in pages))

        pages = self.card.pages[:1]
        self.assertIsInstance(pages, list)
        self.assertEqual(len(pages), 1)
        self.assertTrue(all(isinstance(p, MFUPage) for p in pages))


    def test_page_by_invalid_index(self):
        with self.assertRaises(IndexError):
            self.card.pages[16]

        for t in (object, str, float, complex, bytes, bytearray):
            with self.assertRaises(TypeError):
                self.card.pages[t()]


    def test_page_iterator(self):
        iterable = iter(self.card.pages)
        item = next(iterable)
        self.assertIsInstance(item, MFUPage)
        self.assertIs(item, self.card.pages[0])
        items = list(iterable)
        self.assertEqual(len(items), 15)
        for i, p in enumerate(items):
            self.assertIs(p, self.card.pages[i + 1])


    def test_set_page_from_int(self):
        self.card.pages[0] = 0x11223344
        self.assertEqual(self.card.pages[0].to_int(), 0x11223344)
        self.assertEqual(self.card.pages[0].to_hex(), '11223344')


    def test_set_page_from_bytes(self):
        self.card.pages[0] = bytes([0x11, 0x22, 0x33, 0x44])
        self.assertEqual(self.card.pages[0].to_int(), 0x11223344)
        self.assertEqual(self.card.pages[0].to_hex(), '11223344')
        self.card.pages[0] = b'\x55\x66\x77\x88'
        self.assertEqual(self.card.pages[0].to_int(), 0x55667788)
        self.assertEqual(self.card.pages[0].to_hex(), '55667788')


    def test_set_page_from_bytearray(self):
        self.card.pages[0] = bytearray([0x11, 0x22, 0x33, 0x44])
        self.assertEqual(self.card.pages[0].to_int(), 0x11223344)
        self.assertEqual(self.card.pages[0].to_hex(), '11223344')


    def test_set_page_from_string(self):
        self.card.pages[0] = '\x11\x22\x33\x44'
        self.assertEqual(self.card.pages[0].to_int(), 0x11223344)
        self.assertEqual(self.card.pages[0].to_hex(), '11223344')


    def test_set_page_with_invalid_value(self):
        for t in (object, complex, float, dict, set, list, tuple):
            with self.assertRaises(ValueError):
                self.card.pages[0] = t()
        with self.assertRaises(ValueError):
            self.card.pages[0] = None


    def test_set_page_with_invalid_int_index(self):
        with self.assertRaises(IndexError):
            self.card.pages[len(self.card.pages)] = 0


    def test_set_page_with_invalid_index(self):
        for t in (str, object, complex, float, dict, set, list, tuple):
            with self.assertRaises(TypeError):
                self.card.pages[t()] = 0


    def test_set_page_slices_unsupported(self):
        with self.assertRaises(NotImplementedError):
            self.card.pages[:2] = [0, 0]



unittest.main()
