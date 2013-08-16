using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCryptographyUtilities;

namespace PgpEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                System.Console.WriteLine("Arguments: Path to input file, Path to output file, Path to public key");
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

            string unEncryptedFilePath = Path.GetFullPath(args[0]);//@"c:\test\unEncryptedFile.txt";

            string newFileName = String.Format(@"{0}\{1}_encrypted{2}", Path.GetFullPath(args[1]), Path.GetFileNameWithoutExtension(args[0]), Path.GetExtension(args[0]));
            string outputFilePath = Path.GetFullPath(newFileName); //@"c:\test\";
            string pubKeypath = Path.GetFullPath(args[2]); //@"c:\test\keyPublic.txt";

            // Delete the file if it exists.
            if (File.Exists(outputFilePath))
            {
                File.Delete(outputFilePath);
            }

            FileInfo fi = new FileInfo(unEncryptedFilePath);
            PgpEncryptionKeys encryptionKeys = new PgpEncryptionKeys(pubKeypath);
            PgpEncrypt objPgpEncrypt = new PgpEncrypt(encryptionKeys);

            using (FileStream str = new FileStream(outputFilePath, FileMode.Create))
            {
                objPgpEncrypt.Encrypt(str, fi);
            }
        }
    }
}
