using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using System.Threading;
using CommandLine;
using System.Collections.Generic;

/*
 * .\decryptTest.exe -f C:\dev\test3\Confused\Seatbelt_6vsipfm5.exe.aes -k "testooo" -p -- -group=user
 * 
 * */

namespace decryptTest
{
    class Program
    {  

        public class Options
        {
            [Option('f', "file", Required = true, HelpText = "File to load and execute")]
            public string inFile { get; set; }

            [Option('k', "key", Required = false, HelpText = "Key for decrypting. Automatically AES256 decrypt, load, and execute")]
            public string decryptKey { get; set; }

            [Option('p', "parameters", Required = false, HelpText = "Optional parameter when executing the assembly")]
            public string parameters { get; set; }
        }


        static void Main(string[] args)
        {
            // Remove me and modify me to test decrypting & loading!

            //Parser.Default.Settings.EnableDashDash = true;

            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);
        }

        static void RunOptions(Options opts)
        {
            // Check for inFile first, because it is mandatory 
            if (!(string.IsNullOrEmpty(opts.inFile)))
            {
                byte[] programBytes = loadFile(opts.inFile);
                byte[] decryptedByte = null;

                // AES decrypt, load, and execute with params 
                if (!(string.IsNullOrEmpty(opts.decryptKey)) && !(string.IsNullOrEmpty(opts.parameters)))
                {
                    decryptedByte = aes256Decrypt(programBytes, opts.decryptKey);
                    loadExecAssembly(decryptedByte, opts.parameters);
                }

                // AES decrypt and execute 
                else if (!(string.IsNullOrEmpty(opts.decryptKey)))
                {
                    decryptedByte = aes256Decrypt(programBytes, opts.decryptKey);
                    loadExecAssembly(decryptedByte);
                }

                else if (!(string.IsNullOrEmpty(opts.parameters)))
                {
                    loadExecAssembly(programBytes, opts.parameters);
                }

                else
                {
                    loadExecAssembly(programBytes);
                }
            }


            else
            {
                Console.WriteLine("[-] Wrong arguments");
                return;
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            return;
        }

        // https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1 
        public static byte[] aes256Decrypt(byte[] cipherBytes, string key)
        {
            SHA256Managed shaManaged = new SHA256Managed();
            AesManaged aesManaged = new AesManaged();
            aesManaged.Mode = CipherMode.CBC;
            aesManaged.Padding = PaddingMode.Zeros;
            aesManaged.BlockSize = 128;
            aesManaged.KeySize = 256;

            aesManaged.Key = shaManaged.ComputeHash(Encoding.UTF8.GetBytes(key));

            // Decrypting 
            var ivBytes = new byte[16];
            Array.Copy(cipherBytes, ivBytes, 16);
            aesManaged.IV = ivBytes;
            var decryptor = aesManaged.CreateDecryptor();

            byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 16, cipherBytes.Length - 16);
            aesManaged.Dispose();

            return decryptedBytes;
        }

        public static void loadExecAssembly(byte[] programBytes)
        {
            var loadedAssembly = Assembly.Load(programBytes);
            object[] parameters = new object[] { new string[] { "" } };

            loadedAssembly.EntryPoint.Invoke(null, parameters);
        }

        public static void loadExecAssembly(byte[] programBytes, string userParams)
        {
            var loadedAssembly = Assembly.Load(programBytes);
            object[] parameters = new object[] { new string[] { userParams } };

            loadedAssembly.EntryPoint.Invoke(null, parameters);
        }

        public static byte[] loadFile(string filePath)
        {
            byte[] programBytes = null;

            try
            {
                programBytes = File.ReadAllBytes(filePath);
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); }

            return programBytes;
        }
    }
}