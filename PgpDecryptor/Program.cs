using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PgpEncryptor;
using PgpCryptographyUtilities;

namespace PgpDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                System.Console.WriteLine("Arguments: Path to encrypted file, Output path, Path to private key, passphrase");
                return;
            }
            
            if (!PathValidation.ValidateFilePath(args[0]))
            {
                return;
            }
            if (!PathValidation.ValidateDirectoryPath(args[1]))
            {
                return;
            }
            if (!PathValidation.ValidateFilePath(args[2]))
            {
                return;
            }

            string path = Path.GetFullPath(args[0]);//@"c:\test\MyTest.txt";
            string outputPath = Path.GetFullPath(args[1]); //@"c:\temp";
            string privKeypath = Path.GetFullPath(args[2]); //@"c:\test\keyPrivate.txt";

            PgpDecryptionKeys decryptionKeys = new PgpDecryptionKeys(privKeypath, args[3]);
            PGPDecrypt test = new PGPDecrypt(decryptionKeys);

            using (FileStream fs = File.Open(path, FileMode.Open))
            {
                test.decrypt(fs, outputPath);
                fs.Close();
            }
        }
    }
}
