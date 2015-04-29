using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Drawing.Imaging;
namespace Enigmator
{
    class Program
    {
        private static Bitmap sourceImage;
        private static String sourceText;



        private static string PasswordHash;
        static readonly string SaltKey = "S@LT&KEY";
        static readonly string VIKey = "@1B2c3D4e5F6g7H8";

        public static string Encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
        }
        public static string Decrypt(string encryptedText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }


        #region KodDönüştürmece
        public static string CodeToStr(byte c)
        {
            string Str = "";

            if (c == 32) Str = " ";
            if (c == 33) Str = "!";
            if (c == 34) Str = "\"";
            if (c == 35) Str = "#";
            if (c == 36) Str = "$";
            if (c == 37) Str = "%";
            if (c == 38) Str = "&";
            if (c == 39) Str = "'";
            if (c == 40) Str = "(";
            if (c == 41) Str = ")";
            if (c == 42) Str = "*";
            if (c == 43) Str = "+";
            if (c == 44) Str = ",";
            if (c == 45) Str = "-";
            if (c == 46) Str = ".";
            if (c == 47) Str = "/";
            if (c == 48) Str = "0";
            if (c == 49) Str = "1";
            if (c == 50) Str = "2";
            if (c == 51) Str = "3";
            if (c == 52) Str = "4";
            if (c == 53) Str = "5";
            if (c == 54) Str = "6";
            if (c == 55) Str = "7";
            if (c == 56) Str = "8";
            if (c == 57) Str = "9";
            if (c == 58) Str = ":";
            if (c == 59) Str = ";";
            if (c == 60) Str = "<";
            if (c == 61) Str = "=";
            if (c == 62) Str = ">";
            if (c == 63) Str = "?";
            if (c == 64) Str = "@";
            if (c == 65) Str = "A";
            if (c == 66) Str = "B";
            if (c == 67) Str = "C";
            if (c == 68) Str = "D";
            if (c == 69) Str = "E";
            if (c == 70) Str = "F";
            if (c == 71) Str = "G";
            if (c == 72) Str = "H";
            if (c == 73) Str = "I";
            if (c == 74) Str = "J";
            if (c == 75) Str = "K";
            if (c == 76) Str = "L";
            if (c == 77) Str = "M";
            if (c == 78) Str = "N";
            if (c == 79) Str = "O";
            if (c == 80) Str = "P";
            if (c == 81) Str = "Q";
            if (c == 82) Str = "R";
            if (c == 83) Str = "S";
            if (c == 84) Str = "T";
            if (c == 85) Str = "U";
            if (c == 86) Str = "V";
            if (c == 87) Str = "W";
            if (c == 88) Str = "X";
            if (c == 89) Str = "Y";
            if (c == 90) Str = "Z";
            if (c == 91) Str = "[";
            if (c == 92) Str = "\\";
            if (c == 93) Str = "]";
            if (c == 94) Str = "^";
            if (c == 95) Str = "_";
            if (c == 96) Str = "`";
            if (c == 97) Str = "a";
            if (c == 98) Str = "b";
            if (c == 99) Str = "c";
            if (c == 100) Str = "d";
            if (c == 101) Str = "e";
            if (c == 102) Str = "f";
            if (c == 103) Str = "g";
            if (c == 104) Str = "h";
            if (c == 105) Str = "i";
            if (c == 106) Str = "j";
            if (c == 107) Str = "k";
            if (c == 108) Str = "l";
            if (c == 109) Str = "m";
            if (c == 110) Str = "n";
            if (c == 111) Str = "o";
            if (c == 112) Str = "p";
            if (c == 113) Str = "q";
            if (c == 114) Str = "r";
            if (c == 115) Str = "s";
            if (c == 116) Str = "t";
            if (c == 117) Str = "u";
            if (c == 118) Str = "v";
            if (c == 119) Str = "w";
            if (c == 120) Str = "x";
            if (c == 121) Str = "y";
            if (c == 122) Str = "z";
            if (c == 123) Str = "{";
            if (c == 124) Str = "|";
            if (c == 125) Str = "}";
            if (c == 126) Str = "~";
            if (c == 128) Str = "Ç";
            if (c == 129) Str = "ü";
            if (c == 130) Str = "é";
            if (c == 131) Str = "â";
            if (c == 132) Str = "ä";
            if (c == 133) Str = "à";
            if (c == 134) Str = "å";
            if (c == 135) Str = "ç";
            if (c == 136) Str = "ê";
            if (c == 137) Str = "ë";
            if (c == 138) Str = "è";
            if (c == 139) Str = "ï";
            if (c == 140) Str = "î";
            if (c == 141) Str = "ì";
            if (c == 142) Str = "Ä";
            if (c == 143) Str = "Å";
            if (c == 144) Str = "É";
            if (c == 145) Str = "æ";
            if (c == 146) Str = "Æ";
            if (c == 147) Str = "ô";
            if (c == 148) Str = "ö";
            if (c == 149) Str = "ò";
            if (c == 150) Str = "û";
            if (c == 151) Str = "ù";
            if (c == 152) Str = "ÿ";
            if (c == 153) Str = "Ö";
            if (c == 154) Str = "Ü";
            if (c == 155) Str = "¢";
            if (c == 156) Str = "£";
            if (c == 157) Str = "¥";
            if (c == 158) Str = "₧";
            if (c == 159) Str = "ƒ";
            if (c == 160) Str = "á";
            if (c == 161) Str = "í";
            if (c == 162) Str = "ó";
            if (c == 163) Str = "ú";
            if (c == 164) Str = "ñ";
            if (c == 165) Str = "Ñ";
            if (c == 166) Str = "ª";
            if (c == 167) Str = "º";
            if (c == 168) Str = "¿";
            if (c == 169) Str = "⌐";
            if (c == 170) Str = "¬";
            if (c == 171) Str = "½";
            if (c == 172) Str = "¼";
            if (c == 173) Str = "¡";
            if (c == 174) Str = "«";
            if (c == 175) Str = "»";
            if (c == 176) Str = "░";
            if (c == 177) Str = "▒";
            if (c == 178) Str = "▓";
            if (c == 179) Str = "│";
            if (c == 180) Str = "┤";
            if (c == 181) Str = "╡";
            if (c == 182) Str = "╢";
            if (c == 183) Str = "╖";
            if (c == 184) Str = "╕";
            if (c == 185) Str = "╣";
            if (c == 186) Str = "║";
            if (c == 187) Str = "╗";
            if (c == 188) Str = "╝";
            if (c == 189) Str = "╜";
            if (c == 190) Str = "╛";
            if (c == 191) Str = "┐";
            if (c == 192) Str = "└";
            if (c == 193) Str = "┴";
            if (c == 194) Str = "┬";
            if (c == 195) Str = "├";
            if (c == 196) Str = "─";
            if (c == 197) Str = "┼";
            if (c == 198) Str = "╞";
            if (c == 199) Str = "╟";
            if (c == 200) Str = "╚";
            if (c == 201) Str = "╔";
            if (c == 202) Str = "╩";
            if (c == 203) Str = "╦";
            if (c == 204) Str = "╠";
            if (c == 205) Str = "═";
            if (c == 206) Str = "╬";
            if (c == 207) Str = "╧";
            if (c == 208) Str = "╨";
            if (c == 209) Str = "╤";
            if (c == 210) Str = "╥";
            if (c == 211) Str = "╙";
            if (c == 212) Str = "Ô";
            if (c == 213) Str = "╒";
            if (c == 214) Str = "╓";
            if (c == 215) Str = "╫";
            if (c == 216) Str = "╪";
            if (c == 217) Str = "┘";
            if (c == 218) Str = "┌";
            if (c == 219) Str = "█";
            if (c == 220) Str = "▄";
            if (c == 221) Str = "▌";
            if (c == 222) Str = "▐";
            if (c == 223) Str = "▀";
            if (c == 224) Str = "α";
            if (c == 225) Str = "ß";
            if (c == 226) Str = "Γ";
            if (c == 227) Str = "π";
            if (c == 228) Str = "Σ";
            if (c == 229) Str = "σ";
            if (c == 230) Str = "µ";
            if (c == 231) Str = "τ";
            if (c == 232) Str = "Φ";
            if (c == 233) Str = "Θ";
            if (c == 234) Str = "Ω";
            if (c == 235) Str = "δ";
            if (c == 236) Str = "∞";
            if (c == 237) Str = "φ";
            if (c == 238) Str = "ε";
            if (c == 239) Str = "∩";
            if (c == 240) Str = "≡";
            if (c == 241) Str = "±";
            if (c == 242) Str = "≥";
            if (c == 243) Str = "≤";
            if (c == 244) Str = "⌠";
            if (c == 245) Str = "⌡";
            if (c == 246) Str = "÷";
            if (c == 247) Str = "≈";
            if (c == 248) Str = "≈";
            if (c == 249) Str = "∙";
            if (c == 250) Str = "·";
            if (c == 251) Str = "√";
            if (c == 252) Str = "ⁿ";
            if (c == 253) Str = "²";
            if (c == 254) Str = "■";
            if (c == 255) Str = "";


            return Str;



        }

        public static int StrToCode(string t)
        {
            int Code = 1;


            if (t == " ") Code = 32;
            if (t == "!") Code = 33;
            if (t == "\"") Code = 34;
            if (t == "#") Code = 35;
            if (t == "$") Code = 36;
            if (t == "%") Code = 37;
            if (t == "&") Code = 38;
            if (t == "'") Code = 39;
            if (t == "(") Code = 40;
            if (t == ")") Code = 41;
            if (t == "*") Code = 42;
            if (t == "+") Code = 43;
            if (t == ",") Code = 44;
            if (t == "-") Code = 45;
            if (t == ".") Code = 46;
            if (t == "/") Code = 47;
            if (t == "0") Code = 48;
            if (t == "1") Code = 49;
            if (t == "2") Code = 50;
            if (t == "3") Code = 51;
            if (t == "4") Code = 52;
            if (t == "5") Code = 53;
            if (t == "6") Code = 54;
            if (t == "7") Code = 55;
            if (t == "8") Code = 56;
            if (t == "9") Code = 57;
            if (t == ":") Code = 58;
            if (t == ";") Code = 59;
            if (t == "<") Code = 60;
            if (t == "=") Code = 61;
            if (t == ">") Code = 62;
            if (t == "?") Code = 63;
            if (t == "@") Code = 64;
            if (t == "A") Code = 65;
            if (t == "B") Code = 66;
            if (t == "C") Code = 67;
            if (t == "D") Code = 68;
            if (t == "E") Code = 69;
            if (t == "F") Code = 70;
            if (t == "G") Code = 71;
            if (t == "H") Code = 72;
            if (t == "I") Code = 73;
            if (t == "J") Code = 74;
            if (t == "K") Code = 75;
            if (t == "L") Code = 76;
            if (t == "M") Code = 77;
            if (t == "N") Code = 78;
            if (t == "O") Code = 79;
            if (t == "P") Code = 80;
            if (t == "Q") Code = 81;
            if (t == "R") Code = 82;
            if (t == "S") Code = 83;
            if (t == "T") Code = 84;
            if (t == "U") Code = 85;
            if (t == "V") Code = 86;
            if (t == "W") Code = 87;
            if (t == "X") Code = 88;
            if (t == "Y") Code = 89;
            if (t == "Z") Code = 90;
            if (t == "[") Code = 91;
            if (t == "\\") Code = 92;
            if (t == "]") Code = 93;
            if (t == "^") Code = 94;
            if (t == "_") Code = 95;
            if (t == "`") Code = 96;
            if (t == "a") Code = 97;
            if (t == "b") Code = 98;
            if (t == "c") Code = 99;
            if (t == "d") Code = 100;
            if (t == "e") Code = 101;
            if (t == "f") Code = 102;
            if (t == "g") Code = 103;
            if (t == "h") Code = 104;
            if (t == "i") Code = 105;
            if (t == "j") Code = 106;
            if (t == "k") Code = 107;
            if (t == "l") Code = 108;
            if (t == "m") Code = 109;
            if (t == "n") Code = 110;
            if (t == "o") Code = 111;
            if (t == "p") Code = 112;
            if (t == "q") Code = 113;
            if (t == "r") Code = 114;
            if (t == "s") Code = 115;
            if (t == "t") Code = 116;
            if (t == "u") Code = 117;
            if (t == "v") Code = 118;
            if (t == "w") Code = 119;
            if (t == "x") Code = 120;
            if (t == "y") Code = 121;
            if (t == "z") Code = 122;
            if (t == "{") Code = 123;
            if (t == "|") Code = 124;
            if (t == "}") Code = 125;
            if (t == "~") Code = 126;
            if (t == "Ç") Code = 128;
            if (t == "ü") Code = 129;
            if (t == "é") Code = 130;
            if (t == "â") Code = 131;
            if (t == "ä") Code = 132;
            if (t == "à") Code = 133;
            if (t == "å") Code = 134;
            if (t == "ç") Code = 135;
            if (t == "ê") Code = 136;
            if (t == "ë") Code = 137;
            if (t == "è") Code = 138;
            if (t == "ï") Code = 139;
            if (t == "î") Code = 140;
            if (t == "ì") Code = 141;
            if (t == "Ä") Code = 142;
            if (t == "Å") Code = 143;
            if (t == "É") Code = 144;
            if (t == "æ") Code = 145;
            if (t == "Æ") Code = 146;
            if (t == "ô") Code = 147;
            if (t == "ö") Code = 148;
            if (t == "ò") Code = 149;
            if (t == "û") Code = 150;
            if (t == "ù") Code = 151;
            if (t == "ÿ") Code = 152;
            if (t == "Ö") Code = 153;
            if (t == "Ü") Code = 154;
            if (t == "¢") Code = 155;
            if (t == "£") Code = 156;
            if (t == "¥") Code = 157;
            if (t == "₧") Code = 158;
            if (t == "ƒ") Code = 159;
            if (t == "á") Code = 160;
            if (t == "í") Code = 161;
            if (t == "ó") Code = 162;
            if (t == "ú") Code = 163;
            if (t == "ñ") Code = 164;
            if (t == "Ñ") Code = 165;
            if (t == "ª") Code = 166;
            if (t == "º") Code = 167;
            if (t == "¿") Code = 168;
            if (t == "⌐") Code = 169;
            if (t == "¬") Code = 170;
            if (t == "½") Code = 171;
            if (t == "¼") Code = 172;
            if (t == "¡") Code = 173;
            if (t == "«") Code = 174;
            if (t == "»") Code = 175;
            if (t == "░") Code = 176;
            if (t == "▒") Code = 177;
            if (t == "▓") Code = 178;
            if (t == "│") Code = 179;
            if (t == "┤") Code = 180;
            if (t == "╡") Code = 181;
            if (t == "╢") Code = 182;
            if (t == "╖") Code = 183;
            if (t == "╕") Code = 184;
            if (t == "╣") Code = 185;
            if (t == "║") Code = 186;
            if (t == "╗") Code = 187;
            if (t == "╝") Code = 188;
            if (t == "╜") Code = 189;
            if (t == "╛") Code = 190;
            if (t == "┐") Code = 191;
            if (t == "└") Code = 192;
            if (t == "┴") Code = 193;
            if (t == "┬") Code = 194;
            if (t == "├") Code = 195;
            if (t == "─") Code = 196;
            if (t == "┼") Code = 197;
            if (t == "╞") Code = 198;
            if (t == "╟") Code = 199;
            if (t == "╚") Code = 200;
            if (t == "╔") Code = 201;
            if (t == "╩") Code = 202;
            if (t == "╦") Code = 203;
            if (t == "╠") Code = 204;
            if (t == "═") Code = 205;
            if (t == "╬") Code = 206;
            if (t == "╧") Code = 207;
            if (t == "╨") Code = 208;
            if (t == "╤") Code = 209;
            if (t == "╥") Code = 210;
            if (t == "╙") Code = 211;
            if (t == "Ô") Code = 212;
            if (t == "╒") Code = 213;
            if (t == "╓") Code = 214;
            if (t == "╫") Code = 215;
            if (t == "╪") Code = 216;
            if (t == "┘") Code = 217;
            if (t == "┌") Code = 218;
            if (t == "█") Code = 219;
            if (t == "▄") Code = 220;
            if (t == "▌") Code = 221;
            if (t == "▐") Code = 222;
            if (t == "▀") Code = 223;
            if (t == "α") Code = 224;
            if (t == "ß") Code = 225;
            if (t == "Γ") Code = 226;
            if (t == "π") Code = 227;
            if (t == "Σ") Code = 228;
            if (t == "σ") Code = 229;
            if (t == "µ") Code = 230;
            if (t == "τ") Code = 231;
            if (t == "Φ") Code = 232;
            if (t == "Θ") Code = 233;
            if (t == "Ω") Code = 234;
            if (t == "δ") Code = 235;
            if (t == "∞") Code = 236;
            if (t == "φ") Code = 237;
            if (t == "ε") Code = 238;
            if (t == "∩") Code = 239;
            if (t == "≡") Code = 240;
            if (t == "±") Code = 241;
            if (t == "≥") Code = 242;
            if (t == "≤") Code = 243;
            if (t == "⌠") Code = 244;
            if (t == "⌡") Code = 245;
            if (t == "÷") Code = 246;
            if (t == "≈") Code = 247;
            if (t == "≈") Code = 248;
            if (t == "∙") Code = 249;
            if (t == "·") Code = 250;
            if (t == "√") Code = 251;
            if (t == "ⁿ") Code = 252;
            if (t == "²") Code = 253;
            if (t == "■") Code = 254;
            if (t == "") Code = 255;

            return Code;

        }
        #endregion

        static void Main(string[] args)
        {
            try
            {
                System.Drawing.Image orjinalFoto = null;
                string root = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                string method;
                Console.Write("Choose a Method(Encrypt:1|Decrypt:2) : ");
                method = Console.ReadLine();
                Console.WriteLine("Done..");
                int z = 0;
                string Yazi = "";
                if (method == "2")
                {
                    Console.WriteLine("New: 1 | Filter: 2");
                    string newOrOpen = Console.ReadLine();
                    Console.WriteLine("ok! Pls Wait...");


                    orjinalFoto = System.Drawing.Image.FromFile(root + "\\Decrypt.jpg");
                    sourceImage = new Bitmap(orjinalFoto);
                    Console.Write("PasswordHash: ");
                    PasswordHash = Console.ReadLine();
                    Console.WriteLine("ok! Pls Wait...");
                    Color c;

                    // int tUzunluk = int.Parse(txtKey2.Text.ToString());
                    string t;

                    int e = -1;
                    for (int y = 0; y < sourceImage.Height; y++)
                    {
                        for (int x = 0; x < sourceImage.Width; x++)
                        {


                            if (newOrOpen == "2")
                            {
                                e++;
                                c = ((Bitmap)sourceImage).GetPixel(x, y);
                                int r = c.R; int g = c.G; int b = c.B;

                                if (b != 0)
                                {
                                    Yazi += CodeToStr((byte)b);
                                }
                                else
                                {
                                    if (z == 0)
                                    {
                                        sourceText = Decrypt(Yazi).ToString();
                                        System.IO.File.WriteAllText(root + "\\WriteText.txt", sourceText, Encoding.GetEncoding(1254));
                                        z++;
                                        return;
                                    }
                                }

                            }
                            else
                            {




                                c = ((Bitmap)sourceImage).GetPixel(x, y);
                                int r = c.R; int g = c.G; int b = c.B;

                                e++;
                                if (r != 0)
                                {
                                    Yazi += CodeToStr(c.R);
                                }
                                else
                                {
                                    if (z == 0)
                                    {
                                        sourceText = Decrypt(Yazi).ToString();
                                        System.IO.File.WriteAllText(root + "\\WriteText.txt", sourceText, Encoding.GetEncoding(1254));
                                        z++;
                                        return;
                                    }
                                }


                                e++;
                                if (g != 0)
                                {
                                    Yazi += CodeToStr(c.G);
                                }
                                else
                                {
                                    if (z == 0)
                                    {
                                        sourceText = Decrypt(Yazi).ToString();
                                        System.IO.File.WriteAllText(root + "\\WriteText.txt", sourceText, Encoding.GetEncoding(1254));
                                        z++;
                                        return;
                                    }
                                }


                                e++;
                                if (b != 0)
                                {
                                    Yazi += CodeToStr(c.B);
                                }
                                else
                                {
                                    if (z == 0)
                                    {
                                        sourceText = Decrypt(Yazi).ToString();
                                        System.IO.File.WriteAllText(root + "\\WriteText.txt", sourceText, Encoding.GetEncoding(1254));
                                        z++;
                                        return;
                                    }
                                }


                            }
                        }

                    }
                    //sourceText = Decrypt(Yazi).ToString();
                    System.IO.File.WriteAllText(root + "\\WriteLog.txt", Yazi, Encoding.GetEncoding(1254));

                }
                else
                {

                    sourceText = System.IO.File.ReadAllText(root + "\\text.txt", Encoding.GetEncoding(1254));
                    Console.Write("PasswordHash: ");
                    PasswordHash = Console.ReadLine();
                    Console.WriteLine("ok! Pls Wait...");
                    string Text = Encrypt(sourceText);
                    int tUzunluk = Text.Length;


                    Console.WriteLine("New: 1 | Filter: 2");
                    string newOrOpen = Console.ReadLine();
                    Console.WriteLine("ok! Pls Wait...");

                    Color c;


                    string t;

                    int e = -1;
                    if (newOrOpen == "1")
                    {
                        int uzun = tUzunluk / 3;
                        double karekok = Math.Sqrt(uzun);
                        int ux = (int)karekok + 1;
                        Bitmap bmp = new Bitmap(ux, ux, PixelFormat.Format24bppRgb);
                        sourceImage = new Bitmap(bmp);
                        int r, g, b;

                        for (int y = 0; y < sourceImage.Height; y++)
                        {
                            Random rnd = new Random();
                            for (int x = 0; x < sourceImage.Width; x++)
                            {
                                e++;
                                if (e < tUzunluk) { r = StrToCode(Text.Substring(e, 1)); }
                                else
                                {
                                    if (z == 0) { r = 0; }
                                    else
                                    {
                                        r = rnd.Next(40, 120);
                                    } z++;
                                }

                                e++;
                                if (e < tUzunluk) { g = StrToCode(Text.Substring(e, 1)); }
                                else
                                {
                                    if (z == 0) { g = 0; }
                                    else
                                    {
                                        g = rnd.Next(40, 120);
                                    } z++;
                                }

                                e++;
                                if (e < tUzunluk) { b = StrToCode(Text.Substring(e, 1)); }
                                else
                                {
                                    if (z == 0) { b = 0; }
                                    else
                                    {
                                        b = rnd.Next(40, 120);
                                    } z++;
                                }
                                ((Bitmap)sourceImage).SetPixel(x, y, Color.FromArgb(r, g, b));
                            }

                        }
                    }
                    else
                    {
                        orjinalFoto = System.Drawing.Image.FromFile(root + "\\Encrypt.jpg");
                        sourceImage = new Bitmap(orjinalFoto);

                        for (int y = 0; y < sourceImage.Height; y++)
                        {
                            Random rnd = new Random();
                            for (int x = 0; x < sourceImage.Width; x++)
                            {
                                e++;
                                c = ((Bitmap)sourceImage).GetPixel(x, y);
                                int r = c.R; int g = c.G; int b = c.B;
                                if (e < tUzunluk)
                                {
                                    t = Text.Substring(e, 1);
                                    int n = StrToCode(t);
                                    ((Bitmap)sourceImage).SetPixel(x, y, Color.FromArgb(r, g, n));
                                    //Yazi += b.ToString() + ">"+n.ToString() +",";
                                }
                                else
                                {
                                    if (z == 0)
                                    {
                                        ((Bitmap)sourceImage).SetPixel(x, y, Color.FromArgb(r, g, 0));
                                        //Yazi += b.ToString() + ">0,";
                                    }
                                    else
                                    {
                                        int n1 = rnd.Next(40, 120);
                                        ((Bitmap)sourceImage).SetPixel(x, y, Color.FromArgb(r, g, n1));
                                    }
                                    z++;
                                }

                            }

                        }
                        //System.IO.File.WriteAllText(root + "\\encrypt_log.txt", "uzunluk:" + tUzunluk + "|sourceText:" + sourceText + "|Text:" + Text + "|" + Yazi, Encoding.GetEncoding(1254));
                    }

                    sourceImage.Save(root + "//Decrypt.jpg");
                    Console.WriteLine("Press any key for exit");

                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            finally { Console.WriteLine("finally"); Console.ReadKey(); }
        }
    }
}
