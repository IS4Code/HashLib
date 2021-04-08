using System;
using HashLib;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using TomanuExtensions;
using TomanuExtensions.Utils;
using System.Collections.Generic;
using System.Diagnostics;

namespace HashLibTest
{
    [TestClass]
    public class HashesTest : HashesTestBase
    {
        [TestMethod]
        public void HashLib_Crypto_MD5()
        {
            Test(HashFactory.Crypto.CreateMD5());
        }

        [TestMethod]
        public void HashLib_Crypto_Snefru()
        {
            Test(HashFactory.Crypto.CreateSnefru_4_128());
            Test(HashFactory.Crypto.CreateSnefru_4_256());
            Test(HashFactory.Crypto.CreateSnefru_8_128());
            Test(HashFactory.Crypto.CreateSnefru_8_256());
        }

        [TestMethod]
        public void HashLib_Crypto_HAS160()
        {
            Test(HashFactory.Crypto.CreateHAS160());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_MD5CryptoServiceProvider()
        {
            Test(HashFactory.Crypto.BuildIn.CreateMD5CryptoServiceProvider());
        }

        [TestMethod]
        public void HashLib_Crypto_MD2()
        {
            Test(HashFactory.Crypto.CreateMD2());
        }

        [TestMethod]
        public void HashLib_Crypto_MD4()
        {
            Test(HashFactory.Crypto.CreateMD4());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA224()
        {
            Test(HashFactory.Crypto.CreateSHA224());
        }

        [TestMethod]
        public void HashLib_Crypto_RIPEMD128()
        {
            Test(HashFactory.Crypto.CreateRIPEMD128());
        }

        [TestMethod]
        public void HashLib_Crypto_RIPEMD160()
        {
            Test(HashFactory.Crypto.CreateRIPEMD160());
        }

        [TestMethod]
        public void HashLib_Crypto_Haval()
        {
            Test(HashFactory.Crypto.CreateHaval_3_128());
            Test(HashFactory.Crypto.CreateHaval_4_128());
            Test(HashFactory.Crypto.CreateHaval_5_128());

            Test(HashFactory.Crypto.CreateHaval_3_160());
            Test(HashFactory.Crypto.CreateHaval_4_160());
            Test(HashFactory.Crypto.CreateHaval_5_160());

            Test(HashFactory.Crypto.CreateHaval_3_192());
            Test(HashFactory.Crypto.CreateHaval_4_192());
            Test(HashFactory.Crypto.CreateHaval_5_192());

            Test(HashFactory.Crypto.CreateHaval_3_224());
            Test(HashFactory.Crypto.CreateHaval_4_224());
            Test(HashFactory.Crypto.CreateHaval_5_224());

            Test(HashFactory.Crypto.CreateHaval_3_256());
            Test(HashFactory.Crypto.CreateHaval_4_256());
            Test(HashFactory.Crypto.CreateHaval_5_256());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_JH()
        {
            Test(HashFactory.Crypto.SHA3.CreateJH224());
            Test(HashFactory.Crypto.SHA3.CreateJH256());
            Test(HashFactory.Crypto.SHA3.CreateJH384());
            Test(HashFactory.Crypto.SHA3.CreateJH512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Echo()
        {
            Test(HashFactory.Crypto.SHA3.CreateEcho224());
            Test(HashFactory.Crypto.SHA3.CreateEcho256());
            Test(HashFactory.Crypto.SHA3.CreateEcho384());
            Test(HashFactory.Crypto.SHA3.CreateEcho512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Fugue()
        {
            Test(HashFactory.Crypto.SHA3.CreateFugue224());
            Test(HashFactory.Crypto.SHA3.CreateFugue256());
            Test(HashFactory.Crypto.SHA3.CreateFugue384());
            Test(HashFactory.Crypto.SHA3.CreateFugue512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Groestl()
        {
            Test(HashFactory.Crypto.SHA3.CreateGroestl224());
            Test(HashFactory.Crypto.SHA3.CreateGroestl256());
            Test(HashFactory.Crypto.SHA3.CreateGroestl384());
            Test(HashFactory.Crypto.SHA3.CreateGroestl512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Hamsi()
        {
            Test(HashFactory.Crypto.SHA3.CreateHamsi224());
            Test(HashFactory.Crypto.SHA3.CreateHamsi256());
            Test(HashFactory.Crypto.SHA3.CreateHamsi384());
            Test(HashFactory.Crypto.SHA3.CreateHamsi512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Keccak()
        {
            Test(HashFactory.Crypto.SHA3.CreateKeccak224());
            Test(HashFactory.Crypto.SHA3.CreateKeccak256());
            Test(HashFactory.Crypto.SHA3.CreateKeccak384());
            Test(HashFactory.Crypto.SHA3.CreateKeccak512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Luffa()
        {
            Test(HashFactory.Crypto.SHA3.CreateLuffa224());
            Test(HashFactory.Crypto.SHA3.CreateLuffa256());
            Test(HashFactory.Crypto.SHA3.CreateLuffa384());
            Test(HashFactory.Crypto.SHA3.CreateLuffa512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Shabal()
        {
            Test(HashFactory.Crypto.SHA3.CreateShabal224());
            Test(HashFactory.Crypto.SHA3.CreateShabal256());
            Test(HashFactory.Crypto.SHA3.CreateShabal384());
            Test(HashFactory.Crypto.SHA3.CreateShabal512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_SHAvite3()
        {
            Test(HashFactory.Crypto.SHA3.CreateSHAvite3_224());
            Test(HashFactory.Crypto.SHA3.CreateSHAvite3_256());
            Test(HashFactory.Crypto.SHA3.CreateSHAvite3_384());
            Test(HashFactory.Crypto.SHA3.CreateSHAvite3_512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_SIMD()
        {
            Test(HashFactory.Crypto.SHA3.CreateSIMD224());
            Test(HashFactory.Crypto.SHA3.CreateSIMD256());
            Test(HashFactory.Crypto.SHA3.CreateSIMD384());
            Test(HashFactory.Crypto.SHA3.CreateSIMD512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Skein()
        {
            Test(HashFactory.Crypto.SHA3.CreateSkein224());
            Test(HashFactory.Crypto.SHA3.CreateSkein256());
            Test(HashFactory.Crypto.SHA3.CreateSkein384());
            Test(HashFactory.Crypto.SHA3.CreateSkein512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_CubeHash()
        {
            Test(HashFactory.Crypto.SHA3.CreateCubeHash224());
            Test(HashFactory.Crypto.SHA3.CreateCubeHash256());
            Test(HashFactory.Crypto.SHA3.CreateCubeHash384());
            Test(HashFactory.Crypto.SHA3.CreateCubeHash512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_Blake()
        {
            Test(HashFactory.Crypto.SHA3.CreateBlake224());
            Test(HashFactory.Crypto.SHA3.CreateBlake256());
            Test(HashFactory.Crypto.SHA3.CreateBlake384());
            Test(HashFactory.Crypto.SHA3.CreateBlake512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA3_BlueMidnightWish()
        {
            Test(HashFactory.Crypto.SHA3.CreateBlueMidnightWish224());
            Test(HashFactory.Crypto.SHA3.CreateBlueMidnightWish256());
            Test(HashFactory.Crypto.SHA3.CreateBlueMidnightWish384());
            Test(HashFactory.Crypto.SHA3.CreateBlueMidnightWish512());
        }

        [TestMethod]
        public void HashLib_Crypto_RIPEMD256()
        {
            Test(HashFactory.Crypto.CreateRIPEMD256());
        }

        [TestMethod]
        public void HashLib_Crypto_RIPEMD320()
        {
            Test(HashFactory.Crypto.CreateRIPEMD320());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA1()
        {
            Test(HashFactory.Crypto.CreateSHA1());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA1Managed()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA1Managed());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA1CryptoServiceProvider()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA1CryptoServiceProvider());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA512Managed()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA512Managed());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA512CryptoServiceProvider()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA512CryptoServiceProvider());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA384Managed()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA384Managed());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA384CryptoServiceProvider()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA384CryptoServiceProvider());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA256Managed()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA256Managed());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA512()
        {
            Test(HashFactory.Crypto.CreateSHA512());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA384()
        {
            Test(HashFactory.Crypto.CreateSHA384());
        }

        [TestMethod]
        public void HashLib_Crypto_BuildIn_SHA256CryptoServiceProvider()
        {
            Test(HashFactory.Crypto.BuildIn.CreateSHA256CryptoServiceProvider());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA256()
        {
            Test(HashFactory.Crypto.CreateSHA256());
        }

        [TestMethod]
        public void HashLib_Crypto_Whirlpool()
        {
            Test(HashFactory.Crypto.CreateWhirlpool());
        }

        [TestMethod]
        public void Crypto_ExtremelyLong()
        {
            TestExtremelyLong();
        }

        [TestMethod]
        public void HashLib_Crypto_Gost()
        {
            Test(HashFactory.Crypto.CreateGost());
        }

        [TestMethod]
        public void HashLib_Crypto_Tiger()
        {
            Test(HashFactory.Crypto.CreateTiger_3_192());
            Test(HashFactory.Crypto.CreateTiger_4_192());
        }

        [TestMethod]
        public void HashLib_Crypto_Tiger2()
        {
            Test(HashFactory.Crypto.CreateTiger2());
        }

        [TestMethod]
        public void HashLib_32_AP()
        {
            Test(HashFactory.Hash32.CreateAP());
        }

        [TestMethod]
        public void HashLib_Checksum_Adler32()
        {
            Test(HashFactory.Checksum.CreateAdler32());
        }

        [TestMethod]
        public void HashLib_32_Bernstein()
        {
            Test(HashFactory.Hash32.CreateBernstein());
        }

        [TestMethod]
        public void HashLib_32_Bernstein1()
        {
            Test(HashFactory.Hash32.CreateBernstein1());
        }

        [TestMethod]
        public void HashLib_32_BKDR()
        {
            Test(HashFactory.Hash32.CreateBKDR());
        }

        [TestMethod]
        public void HashLib_Checksum_CRC32()
        {
            Test(HashFactory.Checksum.CreateCRC32_IEEE());
            Test(HashFactory.Checksum.CreateCRC32_CASTAGNOLI());
            Test(HashFactory.Checksum.CreateCRC32_KOOPMAN());
            Test(HashFactory.Checksum.CreateCRC32_Q());
        }

        [TestMethod]
        public void HashLib_32_DEK()
        {
            Test(HashFactory.Hash32.CreateDEK());
        }

        [TestMethod]
        public void HashLib_32_DJB()
        {
            Test(HashFactory.Hash32.CreateDJB());
        }

        [TestMethod]
        public void HashLib_32_ELF()
        {
            Test(HashFactory.Hash32.CreateELF());
        }

        [TestMethod]
        public void HashLib_Checksum_FNV()
        {
            Test(HashFactory.Hash32.CreateFNV());
        }

        [TestMethod]
        public void HashLib_32_FNV1a()
        {
            Test(HashFactory.Hash32.CreateFNV1a());
        }

        [TestMethod]
        public void HashLib_32_Jenkins3()
        {
            Test(HashFactory.Hash32.CreateJenkins3());
        }

        [TestMethod]
        public void HashLib_32_JS()
        {
            Test(HashFactory.Hash32.CreateJS());
        }

        [TestMethod]
        public void HashLib_32_Murmur2()
        {
            Test(HashFactory.Hash32.CreateMurmur2());
        }

        [TestMethod]
        public void HashLib_32_Murmur3()
        {
            Test(HashFactory.Hash32.CreateMurmur3());
        }

        [TestMethod]
        public void HashLib_32_OneAtTime()
        {
            Test(HashFactory.Hash32.CreateOneAtTime());
        }

        [TestMethod]
        public void HashLib_32_PJW()
        {
            Test(HashFactory.Hash32.CreatePJW());
        }

        [TestMethod]
        public void HashLib_32_Rotating()
        {
            Test(HashFactory.Hash32.CreateRotating());
        }

        [TestMethod]
        public void HashLib_32_RS()
        {
            Test(HashFactory.Hash32.CreateRS());
        }

        [TestMethod]
        public void HashLib_32_SDBM()
        {
            Test(HashFactory.Hash32.CreateSDBM());
        }

        [TestMethod]
        public void HashLib_32_ShiftAndXor()
        {
            Test(HashFactory.Hash32.CreateShiftAndXor());
        }

        [TestMethod]
        public void HashLib_32_SuperFast()
        {
            Test(HashFactory.Hash32.CreateSuperFast());
        }

        [TestMethod]
        public void HashLib_64_FNV()
        {
            Test(HashFactory.Hash64.CreateFNV());
        }

        [TestMethod]
        public void HashLib_64_FNV1a()
        {
            Test(HashFactory.Hash64.CreateFNV1a());
        }

        [TestMethod]
        public void HashLib_Checksum_CRC64()
        {
            Test(HashFactory.Checksum.CreateCRC64_ISO());
            Test(HashFactory.Checksum.CreateCRC64_ECMA());
        }

        [TestMethod]
        public void HashLib_64_Murmur2()
        {
            Test(HashFactory.Hash64.CreateMurmur2());
        }

        [TestMethod]
        public void HashLib_128_Murmur3()
        {
            Test(HashFactory.Hash128.CreateMurmur3_128());
        }

        [TestMethod]
        public void HashLib_64_SipHash()
        {
            Test(HashFactory.Hash64.CreateSipHash());
        }

        [TestMethod]
        public void HashLib_Crypto_Grindahl256()
        {
            Test(HashFactory.Crypto.CreateGrindahl256());
        }

        [TestMethod]
        public void HashLib_Crypto_Grindahl512()
        {
            Test(HashFactory.Crypto.CreateGrindahl512());
        }

        [TestMethod]
        public void HashLib_Crypto_Panama()
        {
            Test(HashFactory.Crypto.CreatePanama());
        }

        [TestMethod]
        public void HashLib_Crypto_RadioGatun32()
        {
            Test(HashFactory.Crypto.CreateRadioGatun32());
        }

        [TestMethod]
        public void HashLib_Crypto_RadioGatun64()
        {
            Test(HashFactory.Crypto.CreateRadioGatun64());
        }

        [TestMethod]
        public void HashLib_Crypto_RIPEMD()
        {
            Test(HashFactory.Crypto.CreateRIPEMD());
        }

        [TestMethod]
        public void HashLib_Crypto_SHA0()
        {
            Test(HashFactory.Crypto.CreateSHA0());
        }

        [TestMethod]
        public void TestHashes()
        {

        }

        [TestMethod]
        public void TestConverters()
        {
            {
                var chars = new char[] { '\x1234', '\xABCD' };
                var bytes = Converters.ConvertCharsToBytes(chars);
                CollectionAssert.AreEqual(bytes.ToList(), 
                    Converters.ConvertHexStringToBytes("3412CDAB").ToList());
            }

            {
                var str = "\x1234\xABCD";
                var bytes = Converters.ConvertStringToBytes(str);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("3412CDAB").ToList());
            }

            {
                var str = "\x1234\xABCD";
                var bytes = Converters.ConvertStringToBytes(str, Encoding.Unicode);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("3412CDAB").ToList());
            }

            {
                var shorts = new short[] { 0x1234, 0x7BCD };
                var bytes = Converters.ConvertShortsToBytes(shorts);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("3412CD7B").ToList());
            }

            {
                var ushorts = new ushort[] { 0x1234, 0xABCD };
                var bytes = Converters.ConvertUShortsToBytes(ushorts);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("3412CDAB").ToList());
            }

            {
                var ints = new int[] { 0x12345678, 0x7BCDEF45 };
                var bytes = Converters.ConvertIntsToBytes(ints);
                CollectionAssert.AreEqual(bytes.ToList(), 
                    Converters.ConvertHexStringToBytes("7856341245EFCD7B").ToList());
            }

            {
                var uints = new uint[] { 0x12345678, 0xABCDEF45 };
                var bytes = Converters.ConvertUIntsToBytes(uints);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("7856341245EFCDAB").ToList());
            }

            {
                var longs = new long[] { 0x12345678ABCDEF45, 0x6756EEFFBC456783 };
                var bytes = Converters.ConvertLongsToBytes(longs);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("12345678ABCDEF45").Reverse().Concat(
                        Converters.ConvertHexStringToBytes("6756EEFFBC456783").Reverse()).ToList());
            }

            {
                var ulongs = new ulong[] { 0x12345678ABCDEF45, 0xF756EEFFBC456783 };
                var bytes = Converters.ConvertULongsToBytes(ulongs);
                CollectionAssert.AreEqual(bytes.ToList(),
                    Converters.ConvertHexStringToBytes("12345678ABCDEF45").Reverse().Concat(
                        Converters.ConvertHexStringToBytes("F756EEFFBC456783").Reverse()).ToList());
            }

            {
                var doubles = new double[] { 56.678768, -34.4568768, 10e34, 10e-20, Double.NaN };
                var bytes = Converters.ConvertDoublesToBytes(doubles);

                var b0 = BitConverter.GetBytes(doubles[0]);
                var b1 = BitConverter.GetBytes(doubles[1]);
                var b2 = BitConverter.GetBytes(doubles[2]);
                var b3 = BitConverter.GetBytes(doubles[3]);
                var b4 = BitConverter.GetBytes(doubles[4]);

                CollectionAssert.AreEqual(bytes.ToList(),
                    b0.Concat(b1).Concat(b2).Concat(b3).Concat(b4).ToList());
            }

            {
                var floats = new float[] { 56.678768f, -34.4568768f, 10e34f, 10e-20f, Single.NaN };
                var bytes = Converters.ConvertFloatsToBytes(floats);

                var b0 = BitConverter.GetBytes(floats[0]);
                var b1 = BitConverter.GetBytes(floats[1]);
                var b2 = BitConverter.GetBytes(floats[2]);
                var b3 = BitConverter.GetBytes(floats[3]);
                var b4 = BitConverter.GetBytes(floats[4]);

                CollectionAssert.AreEqual(bytes.ToList(),
                    b0.Concat(b1).Concat(b2).Concat(b3).Concat(b4).ToList());
            }
        }

        [TestMethod]
        public void HashResult()
        {
            for (int i = 0; i < 14; i++)
            {
                HashResult h1 = new HashResult(m_random.NextBytes(i));

                try
                {
                    uint h2 = h1.GetUInt();

                    if (i != 4)
                        Assert.Fail(i.ToString());

                    Assert.IsTrue(Converters.ConvertBytesToUInts(h1.GetBytes())[0] == h2, i.ToString());
                }
                catch
                {
                    if (i == 4)
                        Assert.Fail(i.ToString());
                }

                try
                {
                    ulong h3 = h1.GetULong();

                    if (i != 8)
                        Assert.Fail(i.ToString());

                    Assert.IsTrue(Converters.ConvertBytesToULongs(h1.GetBytes())[0] == h3, i.ToString());
                }
                catch
                {
                    if (i == 8)
                        Assert.Fail(i.ToString());
                }
            }
        }

        [TestMethod()]
        public void Wrappers()

        {
            TestAgainstTestFile(
                HashFactory.Wrappers.HashAlgorithmToHash(
                    HashFactory.Wrappers.HashToHashAlgorithm(
                        HashFactory.Crypto.CreateSHA1()),
                    HashFactory.Crypto.CreateSHA1().BlockSize
                ), TestData.Load(HashFactory.Crypto.CreateSHA1())
            );
        }

        [TestMethod]
        public void HMAC_All()
        {
            TestHMAC(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateMD5CryptoServiceProvider()),
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5()));
            TestHMAC(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateSHA1CryptoServiceProvider()),
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateSHA1()));
            TestHMAC(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateSHA256Managed()),
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateSHA256()));
            TestHMAC(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateSHA384Managed()),
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateSHA384()));
            TestHMAC(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateSHA512Managed()),
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateSHA512()));

            TestKey(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.BuildIn.CreateMD5CryptoServiceProvider()));
            TestKey(HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5()));
        }
    }
}
