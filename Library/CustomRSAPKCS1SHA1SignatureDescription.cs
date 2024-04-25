using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Xades
{
	public sealed class CustomRSAPKCS1SHA1SignatureDescription : SignatureDescription
	{
		public CustomRSAPKCS1SHA1SignatureDescription()
		{
			KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
			DigestAlgorithm = typeof(SHA1CryptoServiceProvider).FullName;
			FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
			DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
		}

		public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
		{
			if (key == null)
				throw new ArgumentNullException(nameof(key));
			var deformatter = new RSAPKCS1SignatureDeformatter(key);
			deformatter.SetHashAlgorithm("SHA1");
			return deformatter;
		}

		public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
		{
			if (key == null)
				throw new ArgumentNullException(nameof(key));
			var formatter = new RSAPKCS1SignatureFormatter(key);
			formatter.SetHashAlgorithm("SHA1");
			return formatter;
		}
	}
}
