﻿using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using System.Threading;

namespace decryptTest
{
    class Program
    {
        public static byte[] aes256Decrypt(string filePath, string key)
        {
            // https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1 
            SHA256Managed shaManaged = new SHA256Managed();
            AesManaged aesManaged = new AesManaged();
            aesManaged.Mode = CipherMode.CBC;
            aesManaged.Padding = PaddingMode.Zeros;
            aesManaged.BlockSize = 128;
            aesManaged.KeySize = 256;

            aesManaged.Key = shaManaged.ComputeHash(Encoding.UTF8.GetBytes(key));
            var cipherBytes = File.ReadAllBytes(filePath);

            // Decrypting 
            var ivBytes = new byte[16];
            Array.Copy(cipherBytes, ivBytes, 16);
            aesManaged.IV = ivBytes;
            var decryptor = aesManaged.CreateDecryptor();

            byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 16, cipherBytes.Length - 16);
            aesManaged.Dispose();

            return decryptedBytes;
        }


        static void Main(string[] args)
        {
            // Remove me and modify me to test decrypting & loading!
/*
            string key = "testo@testo.local";
            string filePath = @"C:\dev\test3\Confused\Seatbelt_2ixueas3.exe.aes";
            var decryptedBytes = aes256Decrypt(filePath, key);
            Console.WriteLine("[+] Decrypted {0}. Loading and executing...\n", filePath);
            Thread.Sleep(2000);
            byte[] confusedBytes = File.ReadAllBytes(@"c:\dev\test3\confused\Seatbelt_2ixueas3.exe");
            Assembly testAssembly = Assembly.Load(confusedBytes);
            //object[] parameters = new object[] { new string[] { "" } };
            object[] parameters = new object[] { new string[] { "-group=user" } };
            testAssembly.EntryPoint.Invoke(null, parameters);

*/            // Write on-disk for debugging purposes 
            //string outPath = @"C:\dev\testotesto\testo\Confused\SharpView.decrypted.exe";
            //File.WriteAllBytes(outPath, decryptedBytes);


            byte[] confusedBytes = File.ReadAllBytes(@"c:\dev\test3\confused\Seatbelt_2ixueas3.exe");
            Assembly testAssembly = Assembly.Load(confusedBytes);
            //object[] parameters = new object[] { new string[] { "" } };
            object[] parameters = new object[] { new string[] { "-group=user" } };
            testAssembly.EntryPoint.Invoke(null, parameters);

            Console.WriteLine("\n" + "Press Enter to shut me down!");
            Console.ReadLine();

        }
    }
}
