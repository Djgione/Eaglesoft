using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.ServiceModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Security.Cryptography;

namespace ES21PDBA
{
    public partial class Form1 : Form
    {
        ISetupService idd;

        byte[] Iv = { 173, 163, 195, 253, 167, 22, 16, 55, 238, 139, 234, 188, 5, 35, 172, 7 };
        byte[] Key = { 148, 101, 108, 89, 166, 3, 62, 83, 226, 186, 49, 132, 210, 179, 80, 161, 104, 33, 68, 235, 45, 160, 169, 180, 126, 235, 149, 134, 22, 16, 58, 227 };

        public Form1()
        {
            InitializeComponent();
        }
        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text == "")
            {
                return;
            }
            int loop = 0;   
            NetTcpBinding binding = new NetTcpBinding();
            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;
            
            string ip = textBox1.Text;
            EndpointIdentity identity = EndpointIdentity.CreateDnsIdentity("localhost");
            EndpointAddress addr = new EndpointAddress(new Uri("net.tcp://" + ip + ":2010/SetupService"), identity);
            ChannelFactory<ISetupService> chn = new ChannelFactory<ISetupService>(binding, addr);
            chn.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None; 
            chn.Credentials.ServiceCertificate.Authentication.RevocationMode = X509RevocationMode.NoCheck;
            chn.Credentials.ClientCertificate.SetCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, "6782cd051aae788f8f10ae14608098e9810d0dcb");
            chn.Open();
            idd = chn.CreateChannel();
            
            IDictionary<string, string> entries = idd.GetServerDatabaseUserInfo();
            foreach (string entry in entries.Values)
            {
                loop = loop + 1;
                if (loop == 7)
                {
                    textBox2.Text = DecryptStringFromBytes(entry, Key, Iv);
                }
                if (loop == 8)
                {
                    textBox3.Text = DecryptStringFromBytes(entry, Key, Iv);
                }
                if (loop == 9)
                {
                    textBox4.Text = DecryptStringFromBytes(entry, Key, Iv);
                }
                if (loop == 10)
                {
                    textBox5.Text = DecryptStringFromBytes(entry, Key, Iv);
                }
            }                       
        }

        public static string DecryptStringFromBytes(string cipherText, byte[] Key, byte[] IV)
        {
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {                
                encryptor.Key = Key;
                encryptor.IV = IV;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);                        
                        cs.Close();
                    }
                    IEnumerable<byte> test = ms.ToArray();
                    cipherText = Encoding.UTF8.GetString(test.Skip(16).ToArray());
                }
            }
            return cipherText;
        }

        [ServiceContract(SessionMode = SessionMode.Required, Namespace = "Patterson.Services.UtilitiesService")]
        public interface ISetupService
        {
            [OperationContract]
            Dictionary<string, string> GetServerDatabaseUserInfo();
        }

        public class implementclass : ISetupService
        {
            public Dictionary<string, string> GetServerDatabaseUserInfo()
            {
                return new Dictionary<string, string>
                {

                };
            }
        }
    }    
}
