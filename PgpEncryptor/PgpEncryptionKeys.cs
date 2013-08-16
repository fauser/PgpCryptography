using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpEncryptor
{
    public class PgpEncryptionKeys
    {
        public PgpPublicKey PublicKey { get; private set; }

        /// <summary>
        /// Initializes a new instance of the EncryptionKeys class.
        /// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
        /// The data is encrypted with the recipients public key and signed with your private key.
        /// </summary>

        /// <param name="publicKeyPath">The key used to encrypt the data</param>
        /// <param name="privateKeyPath">The key used to sign the data.</param>
        /// <param name="passPhrase">The (your) password required to access the private key</param>
        /// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>

        public PgpEncryptionKeys(string publicKeyPath)
        {
            if (!File.Exists(publicKeyPath))
                throw new ArgumentException("Public key file not found", "publicKeyPath");

            PublicKey = ReadPublicKey(publicKeyPath);
        }

        

        #region Public Key
        private PgpPublicKey ReadPublicKey(string publicKeyPath)
        {
            using (Stream keyIn = File.OpenRead(publicKeyPath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                PgpPublicKey foundKey = GetFirstPublicKey(publicKeyRingBundle);
                if (foundKey != null)
                    return foundKey;
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(k => k.IsEncryptionKey)
                    .FirstOrDefault();

                if (key != null)
                    return key;
            }
            return null;
        }

        #endregion
    }
}