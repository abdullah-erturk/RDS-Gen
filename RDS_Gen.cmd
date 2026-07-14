<# : hybrid batch + powershell script
@powershell -noprofile -Window Hidden -c "$param='%*';$ScriptPath='%~f0';iex((Get-Content('%~f0') -Encoding UTF8 -Raw))"&exit/b
#>
Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;
using System.Linq;


public struct Point {
    public BigInteger X;
    public BigInteger Y;
    public bool IsInfinity;
    public Point(BigInteger x, BigInteger y) { X = x; Y = y; IsInfinity = false; }
    public static Point Infinity = new Point { IsInfinity = true };
}

public class Curve {
    public BigInteger P, A, B, N;
    public Point G, K;
    public BigInteger Priv;

    public Curve(BigInteger p, BigInteger a, BigInteger b, BigInteger n, Point g, Point k, BigInteger priv) {
        P = p; A = a; B = b; N = n; G = g; K = k; Priv = priv;
    }

    public BigInteger ModInverse(BigInteger a, BigInteger m) {
        BigInteger m0 = m, t, q;
        BigInteger x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }

    public Point Add(Point p1, Point p2) {
        if (p1.IsInfinity) return p2;
        if (p2.IsInfinity) return p1;

        BigInteger lam;
        if (p1.X == p2.X && p1.Y == p2.Y) {
            BigInteger num = (3 * p1.X * p1.X + A) % P;
            if (num < 0) num += P;
            BigInteger den = ModInverse((2 * p1.Y) % P, P);
            lam = (num * den) % P;
        } else {
            if (p1.X == p2.X) return Point.Infinity;
            BigInteger num = (p2.Y - p1.Y) % P;
            if (num < 0) num += P;
            BigInteger den = ModInverse((p2.X - p1.X + P) % P, P);
            lam = (num * den) % P;
        }

        BigInteger x3 = (lam * lam - p1.X - p2.X) % P;
        if (x3 < 0) x3 += P;
        BigInteger y3 = (lam * (p1.X - x3) - p1.Y) % P;
        if (y3 < 0) y3 += P;

        return new Point(x3, y3);
    }

    public Point Multiply(Point p, BigInteger n) {
        Point r = Point.Infinity;
        Point q = p;
        while (n > 0) {
            if ((n & 1) == 1) r = Add(r, q);
            q = Add(q, q);
            n >>= 1;
        }
        return r;
    }
}
﻿public class LyssaCrypto {

    public static byte[] BigIntToBytesLE(BigInteger n, int l) {
        if (n < 0) n = -n;
        byte[] arr = n.ToByteArray();
        int actualLen = arr.Length;
        if (arr.Length > 0 && arr[arr.Length - 1] == 0) actualLen--;
        byte[] res = new byte[l];
        Array.Copy(arr, res, Math.Min(actualLen, l));
        return res;
    }

    public static BigInteger BytesToBigIntLE(byte[] bytes) {
        byte[] padded = new byte[bytes.Length + 1];
        Array.Copy(bytes, padded, bytes.Length);
        return new BigInteger(padded);
    }

    public static byte[] RC4(byte[] key, byte[] data) {
        byte[] s = new byte[256];
        for (int idx = 0; idx < 256; idx++) s[idx] = (byte)idx;
        int j = 0;
        for (int idx = 0; idx < 256; idx++) {
            j = (j + s[idx] + key[idx % key.Length]) % 256;
            byte temp = s[idx]; s[idx] = s[j]; s[j] = temp;
        }
        int i = 0; j = 0;
        byte[] result = new byte[data.Length];
        for (int k = 0; k < data.Length; k++) {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            byte temp = s[i]; s[i] = s[j]; s[j] = temp;
            int t = (s[i] + s[j]) % 256;
            result[k] = (byte)(data[k] ^ s[t]);
        }
        return result;
    }

    public static string EncodePkey(BigInteger n) {
        if (n == 0) return "";
        string KCHARS = "BCDFGHJKMPQRTVWXY2346789";
        string outStr = "";
        BigInteger currentN = n;
        while (currentN > 0) {
            int remainder = (int)(currentN % 24);
            outStr = KCHARS[remainder] + outStr;
            currentN = currentN / 24;
        }
        outStr = outStr.PadLeft(35, KCHARS[0]);
        var segments = new System.Collections.Generic.List<string>();
        for (int i = 0; i < outStr.Length; i += 5) {
            segments.Add(outStr.Substring(i, 5));
        }
        return string.Join("-", segments);
    }

    public static BigInteger DecodePkey(string k) {
        string keyString = k.Replace("-", "");
        if (keyString.Length % 5 != 0) throw new Exception("Bad length");
        string KCHARS = "BCDFGHJKMPQRTVWXY2346789";
        BigInteger outNum = 0;
        foreach (char c in keyString) {
            int value = KCHARS.IndexOf(c);
            if (value == -1) throw new Exception("Invalid char");
            outNum = outNum * 24 + value;
        }
        return outNum;
    }

        public static BigInteger GetSpkid(string pid) {
        if (pid.Length < 23) throw new Exception("Invalid PID");
        string p1 = pid.Substring(10, 6);
        string p2 = pid.Substring(18, 5);
        string combined = p1 + p2;
        string numStr = combined.Split('-')[0];
        return BigInteger.Parse(numStr);
    }

    public static byte[] MD5Hash(byte[] input) {
        using (MD5 md5 = MD5.Create()) {
            return md5.ComputeHash(input);
        }
    }
    public static byte[] SHA1Hash(byte[] input) {
        using (SHA1 sha1 = SHA1.Create()) {
            return sha1.ComputeHash(input);
        }
    }

    public static BigInteger GenerateRandomBigInt(BigInteger min, BigInteger max) {
        BigInteger range = max - min;
        byte[] rangeBytes = range.ToByteArray();
        int bytesNeeded = rangeBytes.Length;
        if (rangeBytes[bytesNeeded - 1] == 0) bytesNeeded--;
        
        byte[] largeBytes = new byte[bytesNeeded + 32];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
            rng.GetBytes(largeBytes);
        }
        byte[] largePadded = new byte[largeBytes.Length + 1];
        Array.Copy(largeBytes, largePadded, largeBytes.Length);
        BigInteger largeTemp = new BigInteger(largePadded);
        return min + (largeTemp % range);
    }

    public static BigInteger Mod(BigInteger n, BigInteger m) {
        BigInteger r = n % m;
        return r >= 0 ? r : r + m;
    }

    public static byte[] ConcatBytes(params byte[][] arrays) {
        int totalLength = arrays.Sum(a => a.Length);
        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach(var a in arrays) {
            Buffer.BlockCopy(a, 0, result, offset, a.Length);
            offset += a.Length;
        }
        return result;
    }

    public static Curve spkCurveData = new Curve(
        BigInteger.Parse("21782971228112002125810473336838725345308036616026120243639513697227789232461459408261967852943809534324870610618161"),
        1, 0,
        BigInteger.Parse("629063109922370885449"),
        new Point(
            BigInteger.Parse("10692194187797070010417373067833672857716423048889432566885309624149667762706899929433420143814127803064297378514651"),
            BigInteger.Parse("14587399915883137990539191966406864676102477026583239850923355829082059124877792299572208431243410905713755917185109")
        ),
        new Point(
            BigInteger.Parse("3917395608307488535457389605368226854270150445881753750395461980792533894109091921400661704941484971683063487980768"),
            BigInteger.Parse("8858262671783403684463979458475735219807686373661776500155868309933327116988404547349319879900761946444470688332645")
        ),
        BigInteger.Parse("153862071918555979944")
    );

    public static Curve lkpCurveData = new Curve(
        BigInteger.Parse("28688293616765795404141427476803815352899912533728694325464374376776313457785622361119232589082131818578591461837297"),
        1, 0,
        BigInteger.Parse("675048016158598417213"),
        new Point(
            BigInteger.Parse("18999816458520350299014628291870504329073391058325678653840191278128672378485029664052827205905352913351648904170809"),
            BigInteger.Parse("7233699725243644729688547165924232430035643592445942846958231777803539836627943189850381859836033366776176689124317")
        ),
        new Point(
            BigInteger.Parse("7147768390112741602848314103078506234267895391544114241891627778383312460777957307647946308927283757886117119137500"),
            BigInteger.Parse("20525272195909974311677173484301099561025532568381820845650748498800315498040161314197178524020516408371544778243934")
        ),
        BigInteger.Parse("100266970209474387075")
    );

    public static bool ValidateTskey(string pid, string tskey, bool isSpk) {
        try {
            BigInteger keydataInt = DecodePkey(tskey);
            byte[] keydataBytes = BigIntToBytesLE(keydataInt, 21);

            byte[] pidBytesUtf16le = Encoding.Unicode.GetBytes(pid);
            byte[] md5Digest = MD5Hash(pidBytesUtf16le);
            byte[] rk = new byte[16];
            Array.Copy(md5Digest, rk, 5);

            byte[] dc_kdata = RC4(rk, keydataBytes);

            if (dc_kdata.Length < 21) return false;

            byte[] keydata_inner = new byte[7];
            Array.Copy(dc_kdata, 0, keydata_inner, 0, 7);
            byte[] sigdataBytes = new byte[dc_kdata.Length - 7];
            Array.Copy(dc_kdata, 7, sigdataBytes, 0, sigdataBytes.Length);

            BigInteger sigdata = BytesToBigIntLE(sigdataBytes);

            BigInteger h = sigdata & BigInteger.Parse("34359738367"); // 0x7FFFFFFFF
            BigInteger s = (sigdata >> 35) & BigInteger.Parse("147573952589676412927"); // 0x1FFFFFFFFFFFFFFFFF

            Curve curveData = isSpk ? spkCurveData : lkpCurveData;
            Point hK = curveData.Multiply(curveData.K, h);
            Point sG = curveData.Multiply(curveData.G, s);
            Point R = curveData.Add(hK, sG);

            byte[] RxBytes = BigIntToBytesLE(R.X, 48);
            byte[] RyBytes = BigIntToBytesLE(R.Y, 48);

            byte[] sha1Input = ConcatBytes(keydata_inner, RxBytes, RyBytes);
            byte[] md = SHA1Hash(sha1Input);

            byte[] part1Bytes = new byte[4]; Array.Copy(md, 0, part1Bytes, 0, 4);
            byte[] part2Bytes = new byte[4]; Array.Copy(md, 4, part2Bytes, 0, 4);

            BigInteger part1 = BytesToBigIntLE(part1Bytes);
            BigInteger part2Intermediate = BytesToBigIntLE(part2Bytes);
            BigInteger part2 = part2Intermediate >> 29;
            BigInteger ht = (part2 << 32) | part1;

            if (h != ht) return false;

            if (isSpk) {
                BigInteger spkid_from_key = BytesToBigIntLE(keydata_inner) & BigInteger.Parse("137438953471"); // 0x1FFFFFFFFF
                BigInteger spkid_from_pid = GetSpkid(pid);
                return (spkid_from_key == spkid_from_pid);
            } else {
                return true;
            }
        } catch {
            return false;
        }
    }

    public static string GenerateTsKey(string pid, byte[] keydata_inner, bool isSpk) {
        Curve curveData = isSpk ? spkCurveData : lkpCurveData;
        BigInteger privKey = curveData.Priv;

        byte[] pidBytesUtf16le = Encoding.Unicode.GetBytes(pid);
        byte[] md5Digest = MD5Hash(pidBytesUtf16le);
        byte[] rk = new byte[16];
        Array.Copy(md5Digest, rk, 5);

        int attempts = 0;
        while(attempts < 1000) {
            attempts++;
            BigInteger c_nonce = GenerateRandomBigInt(1, curveData.N);

            Point R = curveData.Multiply(curveData.G, c_nonce);

            byte[] RxBytes = BigIntToBytesLE(R.X, 48);
            byte[] RyBytes = BigIntToBytesLE(R.Y, 48);

            byte[] sha1Input = ConcatBytes(keydata_inner, RxBytes, RyBytes);
            byte[] md = SHA1Hash(sha1Input);

            byte[] p1 = new byte[4]; Array.Copy(md, 0, p1, 0, 4);
            byte[] p2i = new byte[4]; Array.Copy(md, 4, p2i, 0, 4);

            BigInteger part1 = BytesToBigIntLE(p1);
            BigInteger part2Intermediate = BytesToBigIntLE(p2i);
            BigInteger part2 = part2Intermediate >> 29;
            BigInteger h = (part2 << 32) | part1;

            BigInteger s = Mod(c_nonce - (privKey * h), curveData.N);

            BigInteger s_masked = s & BigInteger.Parse("147573952589676412927"); // 0x1FFFFFFFFFFFFFFFFF
            if (s_masked != s || s_masked >= BigInteger.Parse("147573952589676412927")) continue;

            BigInteger h_masked = h & BigInteger.Parse("34359738367"); // 0x7FFFFFFFF
            BigInteger sigdata = (s_masked << 35) | h_masked;
            byte[] sigdataBytes = BigIntToBytesLE(sigdata, 14);

            byte[] pkdata = ConcatBytes(keydata_inner, sigdataBytes);
            byte[] pke = RC4(rk, pkdata);

            byte[] pke20 = new byte[20];
            Array.Copy(pke, pke20, 20);
            BigInteger pk = BytesToBigIntLE(pke20);
            string pkstr = EncodePkey(pk);

            if (ValidateTskey(pid, pkstr, isSpk)) {
                return pkstr;
            }
        }
        throw new Exception("Failed to generate a valid key");
    }

    public static string GenerateSpk(string pid) {
        BigInteger spkidNum = GetSpkid(pid);
        byte[] spkdata = BigIntToBytesLE(spkidNum, 7);
        return GenerateTsKey(pid, spkdata, true);
    }

    public static string GenerateLkp(string pid, int countInput, int majorVer, int minorVer, int chid) {
        BigInteger count = countInput;
        BigInteger chidBig = chid;

        BigInteger version = 1;
        if ((majorVer == 5 && minorVer > 0) || majorVer > 5) {
            version = (new BigInteger(majorVer) << 3) | new BigInteger(minorVer);
        }

        BigInteger lkpinfo = (chidBig << 46) |
                             (count << 32) |
                             (new BigInteger(2) << 18) |
                             (new BigInteger(144) << 10) |
                             (version << 3);

        byte[] lkpdata = BigIntToBytesLE(lkpinfo, 7);
        return GenerateTsKey(pid, lkpdata, false);
    }
}

"@ -ReferencedAssemblies "System.Numerics.dll", "System.Security.Cryptography.Algorithms.dll"

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

$lang = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
$isTr = ($lang -eq "tr")

$strings = @{
    Title = if($isTr) { "RDS Gen - made by Abdullah ERTÜRK" } else { "RDS Gen - made by Abdullah ERTÜRK" }
    PidLabel = if($isTr) { "Product ID (PID):" } else { "Product ID (PID):" }
    PidPlaceholder = if($isTr) { "Örn: 00490-92005-99454-AT527" } else { "e.g., 00490-92005-99454-AT527" }
    SpkBtn = if($isTr) { "Lisans Sunucu Kimliği (SPK) Üret" } else { "Generate License Server ID (SPK)" }
    LkpGroup = if($isTr) { "Lisans Anahtar Paketi (LKP) Üret" } else { "Generate License Key Pack (LKP)" }
    CountLabel = if($isTr) { "Lisans Sayısı:" } else { "License Count:" }
    VerLabel = if($isTr) { "Lisans Sürümü ve Tipi:" } else { "License Version and Type:" }
    LkpBtn = if($isTr) { "Lisans Anahtar Paketi (LKP) Üret" } else { "Generate License Key Pack (LKP)" }
    OutputLabel = if($isTr) { "Çıktı:" } else { "Output:" }
    Working = if($isTr) { "Üretiliyor, lütfen bekleyin..." } else { "Working, please wait..." }
    ErrPidReq = if($isTr) { "Hata: Product ID (PID) gerekli." } else { "Error: Product ID (PID) is required." }
    ErrLkpReq = if($isTr) { "Hata: PID, Sayı ve Sürüm gerekli." } else { "Error: PID, Count and Version required." }
    ErrFormat = if($isTr) { "Hata: Geçersiz giriş formatı." } else { "Error: Invalid input format." }
    AboutBtn = if($isTr) { "Hakkında" } else { "About" }
    AboutTitle = if($isTr) { "Hakkında" } else { "About" }
    AboutText = if($isTr) { "Coded by Abdullah ERTÜRK`r`ngithub.com/abdullah-erturk`r`nerturk-dev.netlify.app`r`n`r`nTeşekkürler WitherOrNot ve Lyssa (thecatontheceiling)" } else { "Coded by Abdullah ERTÜRK`r`ngithub.com/abdullah-erturk`r`nerturk-dev.netlify.app`r`n`r`nThanks to WitherOrNot and Lyssa (thecatontheceiling)" }
    HelpBtn = if($isTr) { "Yardım" } else { "Help" }
    HelpTitle = if($isTr) { "Kullanım Kılavuzu" } else { "Usage Guide" }
    HelpText = if($isTr) { "• İşletim sistemi tarafında RDS lisans etkinleştirilirken 'Telefon ile Etkinleştirme' seçilmelidir.`r`n`r`n• Lisans Yöneticisindeki Sunucu Ürün Kimliğini (PID) kopyalayarak bu araçtaki 'Product ID (PID)' alanına yapıştırın.`r`n`r`n• Önce 'Lisans Sunucu Kimliği (SPK) Üret' butonuna tıklayıp sunucunuzu etkinleştirin.`r`n`r`n• Ardından ihtiyacınız olan Lisans Sayısı ve Sürümü seçerek LKP kodunu üretip lisanslarınızı kurabilirsiniz." } else { "• When activating the RDS license on the operating system side, 'Telephone Activation' must be selected.`r`n`r`n• Copy the Server Product ID (PID) from the License Manager and paste it into the 'Product ID (PID)' field in this tool.`r`n`r`n• First, click the 'Generate License Server ID (SPK)' button to activate your server.`r`n`r`n• Then select the required License Count and Version to generate the LKP code and install your licenses." }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = $strings.Title
$form.Size = New-Object System.Drawing.Size(450, 550)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

$fontBold = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)

$lblPid = New-Object System.Windows.Forms.Label
$lblPid.Text = $strings.PidLabel
$lblPid.Location = New-Object System.Drawing.Point(15, 15)
$lblPid.AutoSize = $true
$lblPid.Font = $fontBold
$form.Controls.Add($lblPid)

$txtPid = New-Object System.Windows.Forms.TextBox
$txtPid.Location = New-Object System.Drawing.Point(15, 35)
$txtPid.Size = New-Object System.Drawing.Size(400, 25)
$txtPid.Font = $fontNormal
$form.Controls.Add($txtPid)

$btnSpk = New-Object System.Windows.Forms.Button
$btnSpk.Text = $strings.SpkBtn
$btnSpk.Location = New-Object System.Drawing.Point(15, 65)
$btnSpk.Size = New-Object System.Drawing.Size(400, 30)
$btnSpk.Font = $fontNormal
$form.Controls.Add($btnSpk)

$txtSpkOutput = New-Object System.Windows.Forms.TextBox
$txtSpkOutput.Location = New-Object System.Drawing.Point(15, 100)
$txtSpkOutput.Size = New-Object System.Drawing.Size(400, 60)
$txtSpkOutput.Multiline = $true
$txtSpkOutput.ReadOnly = $true
$txtSpkOutput.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)
$form.Controls.Add($txtSpkOutput)

$lblLkpTitle = New-Object System.Windows.Forms.Label
$lblLkpTitle.Text = $strings.LkpGroup
$lblLkpTitle.Location = New-Object System.Drawing.Point(15, 185)
$lblLkpTitle.AutoSize = $true
$lblLkpTitle.Font = $fontBold
$form.Controls.Add($lblLkpTitle)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = $strings.CountLabel
$lblCount.Location = New-Object System.Drawing.Point(15, 215)
$lblCount.AutoSize = $true
$lblCount.Font = $fontNormal
$form.Controls.Add($lblCount)

$txtCount = New-Object System.Windows.Forms.TextBox
$txtCount.Location = New-Object System.Drawing.Point(15, 235)
$txtCount.Size = New-Object System.Drawing.Size(150, 25)
$txtCount.Font = $fontNormal
$txtCount.MaxLength = 4
$txtCount.Text = "9999"
$form.Controls.Add($txtCount)

$lblVer = New-Object System.Windows.Forms.Label
$lblVer.Text = $strings.VerLabel
$lblVer.Location = New-Object System.Drawing.Point(15, 265)
$lblVer.AutoSize = $true
$lblVer.Font = $fontNormal
$form.Controls.Add($lblVer)

$cmbVer = New-Object System.Windows.Forms.ComboBox
$cmbVer.Location = New-Object System.Drawing.Point(15, 285)
$cmbVer.Size = New-Object System.Drawing.Size(400, 25)
$cmbVer.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbVer.Font = $fontNormal
$form.Controls.Add($cmbVer)

$versions = @(
    @{ Text = "Windows 2000 Per Device"; Value = "001_5_0" }
    @{ Text = "Windows 2000 Internet Connector"; Value = "002_5_0" }
    @{ Text = "Windows Server 2003 Per User"; Value = "003_5_2" }
    @{ Text = "Windows Server 2003 Per Device"; Value = "004_5_2" }
    @{ Text = "Windows Server 2008 (R2) Per Device"; Value = "005_6_0" }
    @{ Text = "Windows Server 2008 (R2) Per User"; Value = "006_6_0" }
    @{ Text = "Windows Server 2008 (R2) VDI Standard"; Value = "009_6_0" }
    @{ Text = "Windows Server 2008 (R2) VDI Premium"; Value = "010_6_0" }
    @{ Text = "Windows Server 2008 (R2) VDI Suite"; Value = "016_6_0" }
    @{ Text = "Windows Server 2012 (R2) Per Device"; Value = "011_6_2" }
    @{ Text = "Windows Server 2012 (R2) Per User"; Value = "012_6_2" }
    @{ Text = "Windows Server 2012 (R2) VDI Suite"; Value = "015_6_2" }
    @{ Text = "Windows Server 2016 Per Device"; Value = "020_10_0" }
    @{ Text = "Windows Server 2016 Per User"; Value = "021_10_0" }
    @{ Text = "Windows Server 2016 VDI Suite"; Value = "022_10_0" }
    @{ Text = "Windows Server 2019 Per Device"; Value = "026_10_1" }
    @{ Text = "Windows Server 2019 Per User"; Value = "027_10_1" }
    @{ Text = "Windows Server 2019 VDI Suite"; Value = "028_10_1" }
    @{ Text = "Windows Server 2022 Per Device"; Value = "029_10_2" }
    @{ Text = "Windows Server 2022 Per User"; Value = "030_10_2" }
    @{ Text = "Windows Server 2022 VDI Suite"; Value = "031_10_2" }
    @{ Text = "Windows Server 2025 Per Device"; Value = "032_10_3" }
    @{ Text = "Windows Server 2025 Per User"; Value = "033_10_3" }
    @{ Text = "Windows Server 2025 VDI Suite"; Value = "034_10_3" }
)

foreach($v in $versions) {
    [void]$cmbVer.Items.Add($v.Text)
}
$cmbVer.SelectedIndex = 19 # Server 2022 Per User

$btnLkp = New-Object System.Windows.Forms.Button
$btnLkp.Text = $strings.LkpBtn
$btnLkp.Location = New-Object System.Drawing.Point(15, 325)
$btnLkp.Size = New-Object System.Drawing.Size(400, 30)
$btnLkp.Font = $fontNormal
$form.Controls.Add($btnLkp)

$txtLkpOutput = New-Object System.Windows.Forms.TextBox
$txtLkpOutput.Location = New-Object System.Drawing.Point(15, 360)
$txtLkpOutput.Size = New-Object System.Drawing.Size(400, 60)
$txtLkpOutput.Multiline = $true
$txtLkpOutput.ReadOnly = $true
$txtLkpOutput.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)
$form.Controls.Add($txtLkpOutput)

$btnSpk.Add_Click({
    $inputPid = $txtPid.Text.Trim()
    if($inputPid -eq "") {
        $txtSpkOutput.Text = $strings.ErrPidReq
        return
    }
    $txtSpkOutput.Text = $strings.Working
    $form.Refresh()
    
    try {
        $spk = [LyssaCrypto]::GenerateSpk($inputPid)
        $txtSpkOutput.Text = "SPK:`r`n" + $spk
    } catch {
        $txtSpkOutput.Text = "Error: " + $_.Exception.Message
    }
})

$btnLkp.Add_Click({
    $inputPid = $txtPid.Text.Trim()
    $countStr = $txtCount.Text.Trim()
    
    if($inputPid -eq "" -or $countStr -eq "") {
        $txtLkpOutput.Text = $strings.ErrLkpReq
        return
    }
    
    $selVerStr = $versions[$cmbVer.SelectedIndex].Value
    $parts = $selVerStr.Split('_')
    $chid = [int]$parts[0]
    $majorVer = [int]$parts[1]
    $minorVer = [int]$parts[2]
    
    $count = 0
    if(-not [int]::TryParse($countStr, [ref]$count) -or $count -lt 1) {
        $txtLkpOutput.Text = $strings.ErrFormat
        return
    }
    
    if ($count -gt 9999) {
        $count = 9999
        $txtCount.Text = "9999"
    }
    
    $txtLkpOutput.Text = $strings.Working
    $form.Refresh()
    
    try {
        $lkp = [LyssaCrypto]::GenerateLkp($inputPid, $count, $majorVer, $minorVer, $chid)
        $txtLkpOutput.Text = "LKP:`r`n" + $lkp
    } catch {
        $txtLkpOutput.Text = "Error: " + $_.Exception.Message
    }
})

$btnAbout = New-Object System.Windows.Forms.Button
$btnAbout.Text = $strings.AboutBtn
$btnAbout.Location = New-Object System.Drawing.Point(15, 450)
$btnAbout.Size = New-Object System.Drawing.Size(100, 30)
$btnAbout.Font = $fontNormal
$btnAbout.Add_Click({
    $aboutForm = New-Object System.Windows.Forms.Form
    $aboutForm.Text = $strings.AboutTitle
    $aboutForm.Size = New-Object System.Drawing.Size(400, 220)
    $aboutForm.StartPosition = "CenterParent"
    $aboutForm.FormBorderStyle = "FixedDialog"
    $aboutForm.MaximizeBox = $false
    $aboutForm.MinimizeBox = $false

    $lblLine1 = New-Object System.Windows.Forms.Label
    $lblLine1.Text = "Coded by Abdullah ERTÜRK"
    $lblLine1.Location = New-Object System.Drawing.Point(20, 20)
    $lblLine1.AutoSize = $true
    $lblLine1.Font = $fontBold
    $aboutForm.Controls.Add($lblLine1)

    $lnkGitHub = New-Object System.Windows.Forms.LinkLabel
    $lnkGitHub.Text = "github.com/abdullah-erturk"
    $lnkGitHub.Location = New-Object System.Drawing.Point(20, 50)
    $lnkGitHub.AutoSize = $true
    $lnkGitHub.Font = $fontNormal
    $lnkGitHub.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://github.com/abdullah-erturk") | Out-Null })
    $aboutForm.Controls.Add($lnkGitHub)

    $lnkWeb = New-Object System.Windows.Forms.LinkLabel
    $lnkWeb.Text = "erturk-dev.netlify.app"
    $lnkWeb.Location = New-Object System.Drawing.Point(20, 75)
    $lnkWeb.AutoSize = $true
    $lnkWeb.Font = $fontNormal
    $lnkWeb.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://erturk-dev.netlify.app") | Out-Null })
    $aboutForm.Controls.Add($lnkWeb)

    $lnkThanks = New-Object System.Windows.Forms.LinkLabel
    $lnkThanks.Text = if($isTr) { "Teşekkürler WitherOrNot ve Lyssa (thecatontheceiling)" } else { "Thanks to WitherOrNot and Lyssa (thecatontheceiling)" }
    $lnkThanks.Location = New-Object System.Drawing.Point(20, 115)
    $lnkThanks.AutoSize = $true
    $lnkThanks.Font = $fontNormal
    $lnkThanks.LinkArea = New-Object System.Windows.Forms.LinkArea(0, 0)
    
    $witherStart = $lnkThanks.Text.IndexOf("WitherOrNot")
    [void]$lnkThanks.Links.Add($witherStart, 11, "https://github.com/WitherOrNot")
    
    $lyssaStart = $lnkThanks.Text.IndexOf("Lyssa")
    [void]$lnkThanks.Links.Add($lyssaStart, 26, "https://github.com/thecatontheceiling")
    
    $lnkThanks.Add_LinkClicked({
        param($sender, $e)
        [System.Diagnostics.Process]::Start($e.Link.LinkData) | Out-Null
    })
    $aboutForm.Controls.Add($lnkThanks)

    $aboutForm.ShowDialog() | Out-Null
})
$form.Controls.Add($btnAbout)

$btnHelp = New-Object System.Windows.Forms.Button
$btnHelp.Text = $strings.HelpBtn
$btnHelp.Location = New-Object System.Drawing.Point(125, 450)
$btnHelp.Size = New-Object System.Drawing.Size(100, 30)
$btnHelp.Font = $fontNormal
$btnHelp.Add_Click({
    [System.Windows.Forms.MessageBox]::Show($strings.HelpText, $strings.HelpTitle, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})
$form.Controls.Add($btnHelp)

$form.ShowDialog() | Out-Null
