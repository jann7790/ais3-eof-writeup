using System;
using System.Collections;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace knock;

internal class Program
{
    private static void Main(string[] args)
    {
        byte[] data = new byte[65];
        int correctIndex = 0;

        for (int i = 0; i < 200; i++)
        {
            if (correctIndex >= 65)
            {
                break;
            }
            data[correctIndex] = (byte)i;
            string[] array = new string[65]
            {
            "f8c1ceb2b36371166efc805824b59252", "ec0f4a549025dfdc98bda08d25593311", "3261390a0dfd09dc16c3987eba10eb53", "66d986ecb8b4d61c648cebdcc2a5ccb2", "fbd5870d0c8964d2c9575a1e55fb7be9", "c0992476cbd06f4f9bb7439ecee81022", "debf803f8b64d47bcdcb8e6fc1854fd3", "3fa81b15cf1210e01155396b648bbe2f", "05880def669376ef5070966617ccdeea", "0c635429f6905f04790ecc942b1bcf86",
            "f70ce87784d549677b28dd0932766833", "790b40de039d3f13dea0e51818e08319", "4a5a99441aa7a885192a0530a407ade0", "0058628c972c658654471b36178f163f", "71f9eaf557aaa691984723bf7536b953", "30cbf3c9e5a0e91168f57f1a5af0b6dc", "d9ccfeb048086c336b1d965aee4a6c3d", "cfd0e95c62ddca1bfd1a902761df59f9", "9798150652e2bd5a24dfbfe5e678be9e", "eb275c9f4a7b3e799dabc6fa56305a13",
            "e7a559cf6b0acbf36087f76a027d55ba", "fe12380219f2285e48928bcb3658550a", "c6b3fb1f238c3a599fcbabb4127ee6b5", "4d15d083b996e4fd0865c79697fb10cd", "4008c526e86cde781976813b1bc3da38", "b0429dde1bbb1372f98a0d1f4c32fa3f", "2447ed4c7337c2c82d2a7bb63f49ec05", "90b247e82e0a0e30c9caf4402840c860", "e17cadf8ee52aa84dfc47d0203d38710", "bf8f4b12d3135fb4af7a1ac72509c9dc",
            "f2ee0d18cf0694678d32797774128ddd", "c6c24338269e7aeab5161fb191e475c2", "23c6afffd93216e493fec87ee9315b86", "0b93d09e1cdaed8d8e0de39531de182a", "1657d03d5b217d1d237db25d8a4d5489", "3498f0744f6059fb2bf7c778d085c909", "ac38e3f1e8d93a6a8c417165a59bce67", "e1b0e8bb077ef11bdee3cc67ddf9cd7b", "4732293cca5121ab05dd5e254d22acee", "fad3b901ba4258ad9fd71a7302df8148",
            "1e02fd1f2f4f22f42fb71a8230c3fa35", "75fcc6674ca64f120eaf3aa911870fc9", "ae8612af96882cb771f1a4d8fdb41fc3", "96bba5d198bfa190c2773516badc221d", "47728b786cbeb69d2c7292925f06aaf1", "3f9031bff26fb95509b8cd353bd0a131", "010863115678f4d19f1d4ac2b2db9697", "e944d1b87ad28a9f7c6cf90680483556", "466d818aafd0cdfc0a9ab3b41a02f5d9", "af0a281c8b0ccb7cb43b4b0345a3bb49",
            "fcb4cb5a6d51bba742fd9d4d73a3449f", "74dfb0110dbb3da8e23bf5fb40af078c", "eb70b854739c9b6cb35f8b2cf77ed64a", "ffe3b6cfa20bb97c909838f7351e4394", "b85ced8f3f11edbd781ee6b0d79fd7b4", "c10b6289b3fd56c1d17ba758960d1c20", "36986e79b356328a1bc32756416bb744", "e2476b0618c7e20c8246f3e274abca03", "9793fd49590b40952f928e7c431d43a9", "c5d774c5e69aea3707e5552b61c85bb2",
            "672e62fd225560292abdf292caf05a02", "6615c852430df05c405d1df7723e944f", "80fb5e9390b54dd8ef51d7c9a86bde14", "c05cec12c67e0c3f1cdb7ae7363008c4", "59e4e7efc94b52ce3ba792cbd7aaabd4"
            };

            int num = 0;
            if (data.Length != array.Length)
            {
                return;
            }
            foreach (byte b in data)
            {
                if (num < correctIndex)
                {
                    num++;
                    continue;
                }
                byte[] obj = new byte[5] { 0, 109, 100, 53, 0 };
                obj[0] = b;
                obj[4] = (byte)num;
                byte[] buffer = obj;
                byte[] array2;
                using (MD5 mD = MD5.Create())
                {
                    array2 = mD.ComputeHash(buffer);
                }
                if (BitConverter.ToString(array2).Replace("-", "").ToLowerInvariant() != array[num])
                {
                    break;
                }
                Console.WriteLine(data[correctIndex]);
                correctIndex++;
                i = 0;
            }

        }
        string result = System.Text.Encoding.UTF8.GetString(data);
        Console.WriteLine(result);

        Console.Read();
    }


    private static void Secret5(byte[] data)
    {
        string[] array = new string[11]
        {
            "9070513d2abf0bd35b85ad5eb35c5df6", "52c57bffd0bcfbf623c6c025a173c942", "2f22859e72889e3ed4fab35d835553ec", "20b1ae9f6d151da6e31a829d6b40f237", "af7a69aef0fcb2e806316f07fa4afcef", "8e91f93608ba248eec95ecab7b1bdc77", "26b1538f0fa8d78053547b689942263f", "a0c9bbf3f8887c340b2ad259c88e0a7d", "4e735bddd60ac8ec6254772a6b33fb87", "beefa351d728e914eeadfe0ac9a561e1",
            "25bd8cf54a60d122584fbbfe73b18087"
        };
        int num = 0;
        if (data.Length != array.Length)
        {
            return;
        }
        foreach (byte b in data)
        {
            byte[] obj = new byte[5] { 0, 109, 100, 53, 0 };
            obj[0] = b;
            obj[4] = (byte)num;
            byte[] buffer = obj;
            byte[] array2;
            using (MD5 mD = MD5.Create())
            {
                array2 = mD.ComputeHash(buffer);
            }
            if (BitConverter.ToString(array2).Replace("-", "").ToLowerInvariant() != array[num])
            {
                return;
            }
            num++;
        }
    }

}
