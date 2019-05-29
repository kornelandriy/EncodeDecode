using System.Linq;
using System.Net.NetworkInformation;

namespace ActiveKey
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var macAddr =
                (from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up
                    select nic.GetPhysicalAddress().GetAddressBytes()).FirstOrDefault();

            var formattedMacAddr = string.Join (":", (from z in macAddr select z.ToString ("X2")).ToArray());
            
            var enc = Encryptor.Encrypt($"username-Some Some,mac-{formattedMacAddr}", "somePass");
            var dec = Encryptor.Decrypt(enc, "somePass");
        }
    }
}