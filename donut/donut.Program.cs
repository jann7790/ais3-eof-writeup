// donut, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// donut.Program
using System;
using System.Security.Cryptography;
using System.Text;

internal class Program
{
	private static int screen_width;

	private static int screen_height;

	private static double thetaSpacing;

	private static double phiSpacing;

	private static double xAngelSpacing;

	private static double zAngelSpacing;

	private static double radius;

	private static double xOffset;

	private static double xAngel;

	private static double zAngel;

	private static double projectZ;

	private static double projectXY;

	private static void Main(string[] args)
	{
		Console.WriteLine("What's your favorite flavor of donuts?");
		string text = Console.ReadLine().ToLower();
		byte[] bytes = Encoding.UTF8.GetBytes(text);
		if (text.Contains("strawberry"))
		{
			Console.ForegroundColor = ConsoleColor.Magenta;
		}
		else if (text.Contains("blue"))
		{
			Console.ForegroundColor = ConsoleColor.Blue;
		}
		else
		{
			try
			{

				int num = int.Parse(text);
                Console.WriteLine(num);
				Console.ReadLine();
                if (1000 <= num && num < 10000)
				{
					using MD5 mD = MD5.Create();
					byte[] array = mD.ComputeHash(bytes);
					BitConverter.ToString(array).Replace("-", string.Empty).ToLower();
					byte[] array2 = new byte[24]
					{
						49, 8, 83, 209, 4, 77, 130, 36, 139, 44,
						248, 52, 172, 0, 207, 23, 17, 27, 97, 254,
						30, 116, 143, 28
					};
					for (int i = 0; i < array2.Length; i++)
					{
						array2[i] ^= array[i % array.Length];
					}
					Console.WriteLine(Encoding.UTF8.GetString(array2));
				}
			}
			catch (Exception)
			{
			}
		}
		int num2 = 0;
		for (int j = 0; j < bytes.Length; j++)
		{
			num2 += bytes[j];
		}
		Random random = new Random(num2);
		screen_width = 119;
		screen_height = 50;
		thetaSpacing = (double)random.Next(1, 10) / 100.0;
		phiSpacing = (double)random.Next(1, 10) / 100.0;
		xAngelSpacing = (double)random.Next(1, 10) / 100.0;
		zAngelSpacing = (double)random.Next(1, 10) / 100.0;
		radius = (double)random.Next(100, 300) / 100.0;
		xOffset = radius - 0.5 + (double)random.Next(100, 500) / 100.0;
		xAngel = random.Next(30, 150);
		zAngel = random.Next(30, 150);
		projectZ = 10.0;
		projectXY = (double)screen_width * projectZ * 1.0 / (8.0 * (radius + xOffset));
		char[,] array3 = new char[screen_height, screen_width];
		double[,] array4 = new double[screen_height, screen_width];
		Console.SetWindowSize(screen_width + 1, screen_height);
		while (true)
		{
			for (int k = 0; k < array3.GetLength(0); k++)
			{
				for (int l = 0; l < array3.GetLength(1); l++)
				{
					array3[k, l] = ' ';
				}
			}
			for (int m = 0; m < array4.GetLength(0); m++)
			{
				for (int n = 0; n < array4.GetLength(1); n++)
				{
					array4[m, n] = 0.0;
				}
			}
			double num3 = Math.Cos(xAngel);
			double num4 = Math.Sin(xAngel);
			double num5 = Math.Cos(zAngel);
			double num6 = Math.Sin(zAngel);
			for (double num7 = 0.0; num7 < Math.PI * 2.0; num7 += thetaSpacing)
			{
				double num8 = Math.Cos(num7);
				double num9 = Math.Sin(num7);
				for (double num10 = 0.0; num10 < Math.PI * 2.0; num10 += phiSpacing)
				{
					double num11 = Math.Cos(num10);
					double num12 = Math.Sin(num10);
					double num13 = xOffset + radius * num8;
					double num14 = radius * num9;
					double num15 = num13 * (num5 * num11 + num4 * num6 * num12) - num14 * num3 * num6;
					double num16 = num13 * (num6 * num11 - num4 * num5 * num12) + num14 * num3 * num5;
					double num17 = projectZ + num3 * num13 * num12 + num14 * num4;
					double num18 = 1.0 / num17;
					int num19 = (int)((double)(screen_width / 2) + projectXY * num18 * num15);
					int num20 = (int)((double)(screen_height / 2) - projectXY * num18 * num16);
					double num21 = num11 * num8 * num6 - num3 * num8 * num12 - num4 * num9 + num5 * (num3 * num9 - num8 * num4 * num12);
					if (num21 > 0.0 && 0 <= num19 && num19 < screen_width && 0 <= num20 && num20 < screen_height && num18 > array4[num20, num19])
					{
						array4[num20, num19] = num18;
						int index = (int)(num21 * 8.0);
						array3[num20, num19] = ".,-~:;=!*#$@"[index];
					}
				}
			}
			xAngel += xAngelSpacing;
			zAngel += zAngelSpacing;
			Console.SetCursorPosition(0, 0);
			for (int num22 = 0; num22 < array3.GetLength(0); num22++)
			{
				for (int num23 = 0; num23 < array3.GetLength(1); num23++)
				{
					Console.Write(array3[num22, num23]);
				}
				Console.WriteLine();
			}
		}
	}
}
