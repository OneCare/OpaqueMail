using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Heijden.DNS;
using System.DirectoryServices;



namespace OpaqueMail.Net
{
    public class PublicKeyResolver
    {

        public X509Certificate2Collection LocatePublicKeyCertificate(string emailAddress)
        {

            X509Certificate2Collection certificates = new X509Certificate2Collection();

            var resolver = new Resolver();
            resolver.Recursion = true;
            resolver.UseCache = true;
            resolver.DnsServer = "8.8.8.8"; // Google Public DNS

            resolver.TimeOut = 1000;
            resolver.Retries = 3;
            resolver.TransportType = Heijden.DNS.TransportType.Tcp;

            const QClass qClass = QClass.IN;



            var directEmailAddress = emailAddress.Replace("@", ".");
            var directDomain = "";

            var response = resolver.Query(directEmailAddress, QType.CERT, qClass);

            if (response.Answers.Count == 0)
            {
                directDomain = emailAddress.Substring(emailAddress.IndexOf("@") + 1);

                response = resolver.Query(directDomain, QType.CERT, qClass);
            }

            if (response.Answers.Count != 0 && response.RecordsCERT[0].RAWKEY != null)
                certificates.Add(new X509Certificate2(response.RecordsCERT[0].RAWKEY));
           
            if (certificates.Count == 0 && (response = resolver.Query("_ldap._tcp." + directDomain, QType.SRV, qClass)) != null)
            {
                var ldapURL = "LDAP://" + response.RecordsSRV[0].TARGET;
                int port;

                if ((port = response.RecordsSRV[0].PORT) != 0)
                {
                    ldapURL += ":" + port.ToString();
                }

                var directoryEntry = new DirectoryEntry(ldapURL);

                var directorySearcher = new DirectorySearcher(directoryEntry);

                directorySearcher.SearchScope = SearchScope.Subtree;

                directorySearcher.Filter = String.Format("(mail={0})", emailAddress);

                directorySearcher.PropertiesToLoad.Add("usercertificate;binary");

                var results = directorySearcher.FindAll();

                foreach (SearchResult result in results)
                {

                    if (result.Properties.Contains("userCertificate"))
                    {
                        Byte[] b = (Byte[])result.Properties["userCertificate"][0];  //Assuming only one certificate per result.
                         certificates.Add(new X509Certificate(b));
                    }
                }
                

            }
           

            return certificates;
            
        }
    }
}
