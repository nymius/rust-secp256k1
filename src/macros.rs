// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

// This is a macro that routinely comes in handy
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl Copy for $thing {}

        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer for FFI interfacing
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer for FFI interfacing
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize { $len }
        }

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        impl Eq for $thing {}

        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                unsafe {
                    use std::intrinsics::copy_nonoverlapping;
                    use std::mem;
                    let mut ret: $thing = mem::uninitialized();
                    copy_nonoverlapping(ret.as_mut_ptr(),
                                        self.as_ptr(),
                                        mem::size_of::<$thing>());
                    ret
                }
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                let &$thing(ref dat) = self;
                &dat[index]
            }
        }

        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[index.start..index.end]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[..index.end]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[index.start..]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[..]
            }
        }

        impl ::serialize::Decodable for $thing {
            fn decode<D: ::serialize::Decoder>(d: &mut D) -> ::std::result::Result<$thing, D::Error> {
                use serialize::Decodable;

                ::assert_type_is_copy::<$ty>();

                d.read_seq(|d, len| {
                    if len != $len {
                        Err(d.error("Invalid length"))
                    } else {
                        unsafe {
                            use std::mem;
                            let mut ret: [$ty; $len] = mem::uninitialized();
                            for i in 0..len {
                                ret[i] = try!(d.read_seq_elt(i, |d| Decodable::decode(d)));
                            }
                            Ok($thing(ret))
                        }
                    }
                })
            }
        }

        impl ::serialize::Encodable for $thing {
            fn encode<S: ::serialize::Encoder>(&self, s: &mut S)
                                               -> ::std::result::Result<(), S::Error> {
                self[..].encode(s)
            }
        }
    }
}


// for testing
macro_rules! hex_slice {
  ($s:expr) => (
    &$s.from_hex().unwrap()[..]
  )
}
