using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
//using Tools.PGP.Crypto;
namespace PgpEncryptor
{
    public class PGPDecrypt
    {
        public PgpDecryptionKeys _decryptionKeys;

        public PGPDecrypt(PgpDecryptionKeys decryptionKeys)
        {
            _decryptionKeys = decryptionKeys;
        }
        public void decrypt(Stream input, string outputpath)
        {
            input = PgpUtilities.GetDecoderStream(input);
            try
            {
                PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
                PgpEncryptedDataList enc;
                PgpObject obj = pgpObjF.NextPgpObject();
                if (obj is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)obj;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
                }
                PgpPrivateKey privKey = _decryptionKeys.PrivateKey;
                PgpPublicKeyEncryptedData pbe = null;
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    if (privKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }
                Stream clear = pbe.GetDataStream(privKey);
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList)
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream output = File.Create(outputpath + "\\" + Ld.FileName);
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, output);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream output = File.Create(outputpath + "\\" + Ld.FileName);
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, output);
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}