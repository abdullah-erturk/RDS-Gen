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
public class LyssaCrypto {

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

$win32ScrollCode = @'
using System;
using System.Runtime.InteropServices;
public class Win32Scroll {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, int wMsg, IntPtr wParam, IntPtr lParam);
}
'@
Add-Type -TypeDefinition $win32ScrollCode | Out-Null
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$ScriptPath`"" -Verb RunAs
    exit
}

$lang = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
$isTr = ($lang -eq "tr")

function Update-Language {
    $script:strings = @{
        Title = if($script:isTr) { "RDS Gen - made by Abdullah ERTÜRK" } else { "RDS Gen - made by Abdullah ERTÜRK" }
        PidLabel = if($script:isTr) { "Product ID (PID):" } else { "Product ID (PID):" }
        PidPlaceholder = if($script:isTr) { "Örn: 00490-92005-99454-AT527" } else { "e.g., 00490-92005-99454-AT527" }
        SpkBtn = if($script:isTr) { "Lisans Sunucu Kimliği (SPK) Üret" } else { "Generate License Server ID (SPK)" }
        LkpGroup = if($script:isTr) { "Lisans Anahtar Paketi (LKP)" } else { "License Key Pack (LKP)" }
        CountLabel = if($script:isTr) { "Lisans Sayısı:" } else { "License Count:" }
        VerLabel = if($script:isTr) { "Lisans Sürümü ve Tipi:" } else { "License Version and Type:" }
        LkpBtn = if($script:isTr) { "Lisans Anahtar Paketi (LKP) Üret" } else { "Generate License Key Pack (LKP)" }
        OutputLabel = if($script:isTr) { "Çıktı:" } else { "Output:" }
        Working = if($script:isTr) { "Üretiliyor, lütfen bekleyin..." } else { "Working, please wait..." }
        ErrPidReq = if($script:isTr) { "Hata: Product ID (PID) gerekli." } else { "Error: Product ID (PID) is required." }
        ErrLkpReq = if($script:isTr) { "Hata: PID, Sayı ve Sürüm gerekli." } else { "Error: PID, Count and Version required." }
        ErrFormat = if($script:isTr) { "Hata: Geçersiz giriş formatı." } else { "Error: Invalid input format." }
        AboutBtn = if($script:isTr) { "Hakkında" } else { "About" }
        AboutTitle = if($script:isTr) { "Hakkında" } else { "About" }
        AboutText = if($script:isTr) { "Coded by Abdullah ERTÜRK`r`ngithub.com/abdullah-erturk`r`nerturk-dev.netlify.app`r`n`r`nTeşekkürler WitherOrNot ve Lyssa (thecatontheceiling)" } else { "Coded by Abdullah ERTÜRK`r`ngithub.com/abdullah-erturk`r`nerturk-dev.netlify.app`r`n`r`nThanks to WitherOrNot and Lyssa (thecatontheceiling)" }
        HelpBtn = if($script:isTr) { "Yardım" } else { "Help" }
        HelpTitle = if($script:isTr) { "Kullanım Kılavuzu" } else { "Usage Guide" }
        HelpText = if($script:isTr) { "  İşletim sistemi tarafında RDS lisans etkinleştirilirken 'Telefon ile Etkinleştirme' seçilmelidir.`r`n`r`n  Lisans Yöneticisindeki Sunucu Ürün Kimliğini (PID) kopyalayarak bu araçtaki 'Product ID (PID)' alanına yapıştırın.`r`n`r`n  Önce 'Lisans Sunucu Kimliği (SPK) Üret' butonuna tıklayıp sunucunuzu etkinleştirin.`r`n`r`n  Ardından ihtiyacınız olan Lisans Sayısı ve Sürümü seçerek LKP kodunu üretip lisanslarınızı kurabilirsiniz." } else { "  When activating the RDS license on the operating system side, 'Telephone Activation' must be selected.`r`n`r`n  Copy the Server Product ID (PID) from the License Manager and paste it into the 'Product ID (PID)' field in this tool.`r`n`r`n  First, click the 'Generate License Server ID (SPK)' button to activate your server.`r`n`r`n  Then select the required License Count and Version to generate the LKP code and install your licenses." }
        Phase1 = if($script:isTr) { "RDS Sıfırla (Adım 1: Kaldır ve Yeniden Başlat)" } else { "Reset RDS (Step 1: Uninstall & Restart)" }
        Phase2 = if($script:isTr) { "RDS Sıfırla (Adım 2: Kur ve Başlat)" } else { "Reset RDS (Step 2: Install & Start)" }
        Phase1Msg = if($script:isTr) { "Bu işlem RDS Lisanslama rolünü sistemden silecek. Sunucunun yeniden başlatılması gerekecek. Devam edilsin mi?" } else { "This will remove the RDS Licensing role. The server will need to be restarted. Continue?" }
        Phase2Msg = if($script:isTr) { "RDS Lisanslama rolü yeniden kurulacak. İşlem 1-2 dakika sürebilir. Devam edilsin mi?" } else { "RDS Licensing role will be reinstalled. This may take 1-2 minutes. Continue?" }
        Phase2Success = if($script:isTr) { "Kurulum tamamlandı ve servis başlatıldı." } else { "Installation completed and service started." }
        SaveSuccess = if($script:isTr) { "Lisans kodları başarıyla kaydedildi:`r`n" } else { "License codes saved successfully:`r`n" }
        SaveError = if($script:isTr) { "Dosya kaydedilirken bir hata oluştu!`r`n" } else { "An error occurred while saving the file!`r`n" }
        CopySpkSuccess = if($script:isTr) { "SPK başarıyla kopyalandı!" } else { "SPK copied successfully!" }
        CopyLkpSuccess = if($script:isTr) { "LKP başarıyla kopyalandı!" } else { "LKP copied successfully!" }
        WarningTitle = if($script:isTr) { "Uyarı" } else { "Warning" }
        InfoTitle = if($script:isTr) { "Bilgi" } else { "Info" }
        SuccessTitle = if($script:isTr) { "Başarılı" } else { "Success" }
        ErrorTitle = if($script:isTr) { "Hata" } else { "Error" }
        ErrNoPidSys = if($script:isTr) { "Sistemden Product ID alınamadı." } else { "Could not retrieve Product ID from system." }
        ErrRegAcc = if($script:isTr) { "Kayıt defterine erişilirken bir hata oluştu." } else { "Error accessing registry." }
        ErrNoSave = if($script:isTr) { "Kaydedilecek lisans kodu bulunamadı!" } else { "No license code found to save!" }
        TitlePid = if($script:isTr) { "Product ID (PID) Nasıl Bulunur?" } else { "How to find Product ID (PID)?" }
        TitleCount = if($script:isTr) { "Lisans Sayısı Nedir?" } else { "What is License Count?" }
        TitleVer = if($script:isTr) { "Lisans Sürümü ve Tipi Nedir?" } else { "What is License Version and Type?" }
        CtxCopy = if($script:isTr) { "Kopyala" } else { "Copy" }
        CtxPaste = if($script:isTr) { "Yapıştır" } else { "Paste" }
        CtxSelectAll = if($script:isTr) { "Tümünü Seç" } else { "Select All" }
    }
    if ($form) { $form.Text = $script:strings.Title }
    if ($titleLabel) { $titleLabel.Text = $script:strings.Title }
    if ($lblPid) { $lblPid.Text = $script:strings.PidLabel }
    if ($btnSpk) { $btnSpk.Text = $script:strings.SpkBtn }
    if ($grpLkp) { $grpLkp.Text = $script:strings.LkpGroup }
    if ($lblCount) { $lblCount.Text = $script:strings.CountLabel }
    if ($lblVer) { $lblVer.Text = $script:strings.VerLabel }
    if ($btnLkp) { $btnLkp.Text = $script:strings.LkpBtn }
    if ($lblSpkOut) { $lblSpkOut.Text = $script:strings.OutputLabel }
    if ($lblLkpOut) { $lblLkpOut.Text = $script:strings.OutputLabel }
    if ($btnSave) {
        if($script:isTr) { $btnSave.Text = "Kaydet" } else { $btnSave.Text = "Save" }
    }
    if ($btnAbout) { $btnAbout.Text = $script:strings.AboutBtn }
    if ($btnHelp) { $btnHelp.Text = $script:strings.HelpBtn }
    if ($grpSpk) {
        if($script:isTr) { $grpSpk.Text = "SPK İşlemleri" } else { $grpSpk.Text = "SPK Operations" }
    }
    if ($btnLang) {
        if($script:isTr) { $btnLang.Text = "EN" } else { $btnLang.Text = "TR" }
    }
    if ($script:iPhase1) { $script:iPhase1.Text = $script:strings.Phase1 }
    if ($script:iPhase2) { $script:iPhase2.Text = $script:strings.Phase2 }
    if ($iCopy) { $iCopy.Text = $script:strings.CtxCopy }
    if ($iPaste) { $iPaste.Text = $script:strings.CtxPaste }
    if ($iSelect) { $iSelect.Text = $script:strings.CtxSelectAll }
    if ($iCopy2) { $iCopy2.Text = $script:strings.CtxCopy }
    if ($iSelect2) { $iSelect2.Text = $script:strings.CtxSelectAll }
}
Update-Language

$form = New-Object System.Windows.Forms.Form
$form.Text = $strings.Title
$form.Size = New-Object System.Drawing.Size(390, 605)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "None"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.Opacity = 0
$form.Add_Load({
    $script:fadeTimer = New-Object System.Windows.Forms.Timer
    $script:fadeTimer.Interval = 10
    $script:fadeTimer.Add_Tick({
        $form.Opacity += 0.05
        if ($form.Opacity -ge 1) {
            $script:fadeTimer.Stop()
            $script:fadeTimer.Dispose()
        }
    })
    $script:fadeTimer.Start()
})

$form.Add_Paint({
    param($sender, $e)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::Gray, 1)
    $e.Graphics.DrawRectangle($pen, 0, 0, ($form.Width - 1), ($form.Height - 1))
})

$titleBar = New-Object System.Windows.Forms.Panel
$titleBar.Height = 30
$titleBar.Dock = [System.Windows.Forms.DockStyle]::Top
$titleBar.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = $strings.Title
$titleLabel.Location = New-Object System.Drawing.Point(10, 5)
$titleLabel.AutoSize = $true
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titleLabel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$titleBar.Controls.Add($titleLabel)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "X"
$btnClose.Width = 40
$btnClose.Dock = [System.Windows.Forms.DockStyle]::Right
$btnClose.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnClose.FlatAppearance.BorderSize = 0
$btnClose.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$btnClose.ForeColor = [System.Drawing.Color]::White
$btnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClose.Add_Click({ $form.Close() })
$btnClose.Add_MouseEnter({ $btnClose.BackColor = [System.Drawing.Color]::Red })
$btnClose.Add_MouseLeave({ $btnClose.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) })

$btnMinimize = New-Object System.Windows.Forms.Button
$btnMinimize.Text = "-"
$btnMinimize.Width = 40
$btnMinimize.Dock = [System.Windows.Forms.DockStyle]::Right
$btnMinimize.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnMinimize.FlatAppearance.BorderSize = 0
$btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$btnMinimize.ForeColor = [System.Drawing.Color]::White
$btnMinimize.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnMinimize.Add_Click({ $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized })
$btnMinimize.Add_MouseEnter({ $btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(63, 63, 65) })
$btnMinimize.Add_MouseLeave({ $btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) })

$btnLang = New-Object System.Windows.Forms.Button
if ($isTr) {
    $btnLang.Text = 'EN'
} else {
    $btnLang.Text = 'TR'
}
$btnLang.Width = 40
$btnLang.Dock = [System.Windows.Forms.DockStyle]::Right
$btnLang.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnLang.FlatAppearance.BorderSize = 0
$btnLang.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$btnLang.ForeColor = [System.Drawing.Color]::White
$btnLang.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnLang.Add_MouseEnter({ $btnLang.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 65) })
$btnLang.Add_MouseLeave({ $btnLang.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) })
$btnLang.Add_Click({
    $script:isTr = -not $script:isTr
    Update-Language
})
$titleBar.Controls.Add($btnLang)
$titleBar.Controls.Add($btnMinimize)
$titleBar.Controls.Add($btnClose)

$dragAction = {
    param($sender, $e)
    if($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        $script:drag = $true
        $script:dragCursor = [System.Windows.Forms.Cursor]::Position
        $script:dragFormLoc = $sender.FindForm().Location
    }
}
$moveAction = {
    param($sender, $e)
    if($script:drag) {
        $newX = $script:dragFormLoc.X + ([System.Windows.Forms.Cursor]::Position.X - $script:dragCursor.X)
        $newY = $script:dragFormLoc.Y + ([System.Windows.Forms.Cursor]::Position.Y - $script:dragCursor.Y)
        $sender.FindForm().Location = New-Object System.Drawing.Point($newX, $newY)
    }
}
$upAction = {
    $script:drag = $false
}

$titleBar.Add_MouseDown($dragAction)
$titleBar.Add_MouseMove($moveAction)
$titleBar.Add_MouseUp($upAction)
$titleLabel.Add_MouseDown($dragAction)
$titleLabel.Add_MouseMove($moveAction)
$titleLabel.Add_MouseUp($upAction)

$form.Controls.Add($titleBar)

$mainPanel = New-Object System.Windows.Forms.Panel
$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$mainPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.Controls.Add($mainPanel)
$mainPanel.BringToFront()

$fontBold = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)

$ctxRenderer = New-Object System.Windows.Forms.ToolStripSystemRenderer

$ctxEditable = New-Object System.Windows.Forms.ContextMenuStrip
$ctxEditable.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$ctxEditable.ForeColor = [System.Drawing.Color]::White
$ctxEditable.ShowImageMargin = $false
$ctxEditable.Renderer = $ctxRenderer
$iCopy = $ctxEditable.Items.Add($script:strings.CtxCopy)
$iCopy.Add_Click({ if ($ctxEditable.SourceControl.SelectionLength -gt 0) { $ctxEditable.SourceControl.Copy() } })
$iPaste = $ctxEditable.Items.Add($script:strings.CtxPaste)
$iPaste.Add_Click({ $ctxEditable.SourceControl.Paste() })
$iSelect = $ctxEditable.Items.Add($script:strings.CtxSelectAll)
$iSelect.Add_Click({ $ctxEditable.SourceControl.SelectAll() })

$ctxReadOnly = New-Object System.Windows.Forms.ContextMenuStrip
$ctxReadOnly.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$ctxReadOnly.ForeColor = [System.Drawing.Color]::White
$ctxReadOnly.ShowImageMargin = $false
$ctxReadOnly.Renderer = $ctxRenderer
$iCopy2 = $ctxReadOnly.Items.Add($script:strings.CtxCopy)
$iCopy2.Add_Click({ if ($ctxReadOnly.SourceControl.SelectionLength -gt 0) { $ctxReadOnly.SourceControl.Copy() } })
$iSelect2 = $ctxReadOnly.Items.Add($script:strings.CtxSelectAll)
$iSelect2.Add_Click({ $ctxReadOnly.SourceControl.SelectAll() })

function Show-CustomMsgBox {
    param(
        [string]$message,
        [string]$title,
        [string]$buttons = "OK"
    )
    
    $msgForm = New-Object System.Windows.Forms.Form
    $msgForm.Text = $title
    $msgForm.StartPosition = "CenterParent"
    $msgForm.FormBorderStyle = "None"
    $msgForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $msgForm.ShowInTaskbar = $false
    $msgForm.Opacity = 0
    $msgForm.KeyPreview = $true
    $msgForm.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape -or $e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $msgForm.Close()
        }
    })
    $msgForm.Add_Load({
        $script:fadeTimerMsg = New-Object System.Windows.Forms.Timer
        $script:fadeTimerMsg.Interval = 10
        $script:fadeTimerMsg.Add_Tick({
            $msgForm.Opacity += 0.1
            if ($msgForm.Opacity -ge 1) {
                $script:fadeTimerMsg.Stop()
                $script:fadeTimerMsg.Dispose()
            }
        })
        $script:fadeTimerMsg.Start()
    })

    $titlePanel = New-Object System.Windows.Forms.Panel
    $titlePanel.Size = New-Object System.Drawing.Size(350, 30)
    $titlePanel.Location = New-Object System.Drawing.Point(0, 0)
    $titlePanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $titlePanel.Add_MouseDown({ $script:draggingMsg = $true; $script:dragCursorMsg = [System.Windows.Forms.Cursor]::Position; $script:dragFormMsg = $msgForm.Location })
    $titlePanel.Add_MouseMove({ if ($script:draggingMsg) { $msgForm.Location = New-Object System.Drawing.Point($script:dragFormMsg.X + ([System.Windows.Forms.Cursor]::Position.X - $script:dragCursorMsg.X), $script:dragFormMsg.Y + ([System.Windows.Forms.Cursor]::Position.Y - $script:dragCursorMsg.Y)) } })
    $titlePanel.Add_MouseUp({ $script:draggingMsg = $false })
    $msgForm.Controls.Add($titlePanel)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = $title
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $titleLabel.Location = New-Object System.Drawing.Point(10, 7)
    $titleLabel.AutoSize = $true
    $titleLabel.Add_MouseDown({ $script:draggingMsg = $true; $script:dragCursorMsg = [System.Windows.Forms.Cursor]::Position; $script:dragFormMsg = $msgForm.Location })
    $titleLabel.Add_MouseMove({ if ($script:draggingMsg) { $msgForm.Location = New-Object System.Drawing.Point($script:dragFormMsg.X + ([System.Windows.Forms.Cursor]::Position.X - $script:dragCursorMsg.X), $script:dragFormMsg.Y + ([System.Windows.Forms.Cursor]::Position.Y - $script:dragCursorMsg.Y)) } })
    $titleLabel.Add_MouseUp({ $script:draggingMsg = $false })
    $titlePanel.Controls.Add($titleLabel)

    $btnClose = New-Object System.Windows.Forms.Label
    $btnClose.Text = "X"
    $btnClose.ForeColor = [System.Drawing.Color]::White
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnClose.Location = New-Object System.Drawing.Point(325, 7)
    $btnClose.AutoSize = $true
    $btnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnClose.Add_Click({ $msgForm.Close() })
    $titlePanel.Controls.Add($btnClose)

    $lblMsg = New-Object System.Windows.Forms.Label
    $lblMsg.Text = $message
    $lblMsg.ForeColor = [System.Drawing.Color]::White
    $lblMsg.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Regular)
    $lblMsg.Location = New-Object System.Drawing.Point(20, 50)
    $lblMsg.MaximumSize = New-Object System.Drawing.Size(310, 0)
    $lblMsg.AutoSize = $true
    $msgForm.Controls.Add($lblMsg)

    $reqHeight = $lblMsg.PreferredHeight + 110
    if ($reqHeight -lt 140) { $reqHeight = 140 }

    $msgForm.Size = New-Object System.Drawing.Size(350, $reqHeight)

    $script:msgResult = ""

    if ($buttons -eq "YesNo") {
        $btnYes = New-Object System.Windows.Forms.Button
        if($script:isTr) { $btnYes.Text = "Evet" } else { $btnYes.Text = "Yes" }
        $btnYes.Location = New-Object System.Drawing.Point(160, ($reqHeight - 45))
        $btnYes.Size = New-Object System.Drawing.Size(80, 30)
        $btnYes.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnYes.FlatAppearance.BorderSize = 0
        $btnYes.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
        $btnYes.ForeColor = [System.Drawing.Color]::White
        $btnYes.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btnYes.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(95, 95, 100) })
        $btnYes.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80) })
        $btnYes.Add_Click({ $script:msgResult = "Yes"; $msgForm.Close() })
        $msgForm.Controls.Add($btnYes)

        $btnNo = New-Object System.Windows.Forms.Button
        if($script:isTr) { $btnNo.Text = "Hayır" } else { $btnNo.Text = "No" }
        $btnNo.Location = New-Object System.Drawing.Point(250, ($reqHeight - 45))
        $btnNo.Size = New-Object System.Drawing.Size(80, 30)
        $btnNo.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnNo.FlatAppearance.BorderSize = 0
        $btnNo.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
        $btnNo.ForeColor = [System.Drawing.Color]::White
        $btnNo.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btnNo.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(95, 95, 100) })
        $btnNo.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80) })
        $btnNo.Add_Click({ $script:msgResult = "No"; $msgForm.Close() })
        $msgForm.Controls.Add($btnNo)
    } else {
        $btnOk = New-Object System.Windows.Forms.Button
        if($script:isTr) { $btnOk.Text = "Tamam" } else { $btnOk.Text = "OK" }
        $btnOk.Location = New-Object System.Drawing.Point(250, ($reqHeight - 45))
        $btnOk.Size = New-Object System.Drawing.Size(80, 30)
        $btnOk.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnOk.FlatAppearance.BorderSize = 0
        $btnOk.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
        $btnOk.ForeColor = [System.Drawing.Color]::White
        $btnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btnOk.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(95, 95, 100) })
        $btnOk.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80) })
        $btnOk.Add_Click({ $script:msgResult = "OK"; $msgForm.Close() })
        $msgForm.Controls.Add($btnOk)
    }

    [void]$msgForm.ShowDialog()
    return $script:msgResult
}

$grpSpk = New-Object System.Windows.Forms.GroupBox
$grpSpk.Text = "SPK İşlemleri"
$grpSpk.ForeColor = [System.Drawing.Color]::White
$grpSpk.Font = $fontBold
$grpSpk.Location = New-Object System.Drawing.Point(15, 10)
$grpSpk.Size = New-Object System.Drawing.Size(360, 205)
$mainPanel.Controls.Add($grpSpk)

$lblPid = New-Object System.Windows.Forms.Label
$lblPid.Text = $strings.PidLabel
$lblPid.Location = New-Object System.Drawing.Point(15, 25)
$lblPid.AutoSize = $true
$lblPid.Font = $fontBold
$lblPid.ForeColor = [System.Drawing.Color]::White
$lblPid.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$grpSpk.Controls.Add($lblPid)

$lnkPidHelp = New-Object System.Windows.Forms.LinkLabel
$lnkPidHelp.Text = "[?]"
$lnkPidHelp.Location = New-Object System.Drawing.Point(325, 25)
$lnkPidHelp.AutoSize = $true
$lnkPidHelp.Font = $fontNormal
$lnkPidHelp.LinkColor = [System.Drawing.Color]::DeepSkyBlue
$lnkPidHelp.ActiveLinkColor = [System.Drawing.Color]::White
$lnkPidHelp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lnkPidHelp.LinkBehavior = [System.Windows.Forms.LinkBehavior]::NeverUnderline
$lnkPidHelp.Add_Click({
    $msg = if($isTr) { "1. Sunucu Yöneticisi'ni açın.`r`n2. Araçlar > Uzak Masaüstü Hizmetleri > Uzak Masaüstü Lisans Yöneticisi'ni seçin.`r`n3. Sunucunuza sağ tıklayıp Özellikler'e girin.`r`n4. Yükleme Yöntemi sekmesinde bağlantı yöntemini 'Telefon' seçin.`r`n5. Gerekli Bilgiler sekmesindeki bilgileri doldurun.`r`n6. Sunucuya sağ tıklayıp 'Sunucuyu Etkinleştir' deyin.`r`n7. Karşınıza çıkan sihirbazdaki 'Ürün Kimliği' (Product ID) kodunu kopyalayın." } else { "1. Open Server Manager.`r`n2. Tools > Remote Desktop Services > Remote Desktop Licensing Manager.`r`n3. Right click your server > Properties.`r`n4. Connection Method: Telephone.`r`n5. Fill required info.`r`n6. Right click server > Activate Server.`r`n7. Copy the 'Product ID' from the wizard." }
    Show-CustomMsgBox $msg $script:strings.TitlePid
})
$grpSpk.Controls.Add($lnkPidHelp)

$txtPid = New-Object System.Windows.Forms.TextBox
$txtPid.Location = New-Object System.Drawing.Point(15, 50)
$txtPid.Size = New-Object System.Drawing.Size(290, 25)
$txtPid.Font = $fontNormal
$txtPid.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtPid.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtPid.ForeColor = [System.Drawing.Color]::White
$txtPid.ContextMenuStrip = $ctxEditable
$grpSpk.Controls.Add($txtPid)

$styleButton = {
    param($btn, $isPrimary)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.FlatAppearance.BorderSize = 0
    if ($isPrimary) {
        $btn.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
        $btn.ForeColor = [System.Drawing.Color]::White
        $btn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(95, 95, 100) })
        $btn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80) })
    } else {
        $btn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 55)
        $btn.ForeColor = [System.Drawing.Color]::White
        $btn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(70, 70, 75) })
        $btn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 55) })
    }
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
}

$btnScanPid = New-Object System.Windows.Forms.Button
$btnScanPid.Text = [char]::ConvertFromUtf32(0x1F50D)
$btnScanPid.Location = New-Object System.Drawing.Point(315, 49)
$btnScanPid.Size = New-Object System.Drawing.Size(30, 27)
$btnScanPid.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 10, [System.Drawing.FontStyle]::Regular)
&$styleButton $btnScanPid $false
$btnScanPid.Add_Click({
    try {
        $rdsPid = $null
        try {
            $wmiTS = Get-CimInstance -Class Win32_TSLicenseServer -ErrorAction SilentlyContinue
            if ($wmiTS -and $wmiTS.ProductId) {
                $rdsPid = $wmiTS.ProductId
            }
        } catch {}

        if ($rdsPid) {
            $txtPid.Text = $rdsPid
        } else {
            $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64).OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            if ($regKey) { $sysPid = $regKey.GetValue("ProductId") } else { $sysPid = $null }
            
            if ($sysPid) {
                $txtPid.Text = $sysPid
            } else {
                Show-CustomMsgBox $script:strings.ErrNoPidSys $script:strings.ErrorTitle
            }
        }
    } catch {
        Show-CustomMsgBox $script:strings.ErrRegAcc $script:strings.ErrorTitle
    }
})
$grpSpk.Controls.Add($btnScanPid)

$btnSpk = New-Object System.Windows.Forms.Button
$btnSpk.Text = $strings.SpkBtn
$btnSpk.Location = New-Object System.Drawing.Point(15, 90)
$btnSpk.Size = New-Object System.Drawing.Size(330, 30)
$btnSpk.Font = $fontNormal
&$styleButton $btnSpk $true
$grpSpk.Controls.Add($btnSpk)

$txtSpkOutput = New-Object System.Windows.Forms.TextBox
$txtSpkOutput.Location = New-Object System.Drawing.Point(15, 130)
$txtSpkOutput.Size = New-Object System.Drawing.Size(290, 60)
$txtSpkOutput.Multiline = $true
$txtSpkOutput.ReadOnly = $true
$txtSpkOutput.Font = New-Object System.Drawing.Font("Consolas", 8, [System.Drawing.FontStyle]::Regular)
$txtSpkOutput.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtSpkOutput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtSpkOutput.ForeColor = [System.Drawing.Color]::White
$txtSpkOutput.ContextMenuStrip = $ctxReadOnly
$grpSpk.Controls.Add($txtSpkOutput)

$btnCopySpk = New-Object System.Windows.Forms.Button
$btnCopySpk.Text = [char]::ConvertFromUtf32(0x1F4CB)
$btnCopySpk.Location = New-Object System.Drawing.Point(315, 145)
$btnCopySpk.Size = New-Object System.Drawing.Size(30, 30)
$btnCopySpk.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 10, [System.Drawing.FontStyle]::Regular)
&$styleButton $btnCopySpk $false
$btnCopySpk.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($txtSpkOutput.Text)) {
        [System.Windows.Forms.Clipboard]::SetText($txtSpkOutput.Text.Replace("SPK:`r`n", "").Trim())
        Show-CustomMsgBox $script:strings.CopySpkSuccess $script:strings.InfoTitle
    }
})
$grpSpk.Controls.Add($btnCopySpk)

$grpLkp = New-Object System.Windows.Forms.GroupBox
$grpLkp.Text = $strings.LkpGroup
$grpLkp.ForeColor = [System.Drawing.Color]::White
$grpLkp.Font = $fontBold
$grpLkp.Location = New-Object System.Drawing.Point(15, 230)
$grpLkp.Size = New-Object System.Drawing.Size(360, 195)
$mainPanel.Controls.Add($grpLkp)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = $strings.CountLabel
$lblCount.Location = New-Object System.Drawing.Point(245, 25)
$lblCount.AutoSize = $true
$lblCount.Font = $fontNormal
$lblCount.ForeColor = [System.Drawing.Color]::White
$lblCount.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$grpLkp.Controls.Add($lblCount)

$lnkCountHelp = New-Object System.Windows.Forms.LinkLabel
$lnkCountHelp.Text = "[?]"
$lnkCountHelp.Location = New-Object System.Drawing.Point(325, 25)
$lnkCountHelp.AutoSize = $true
$lnkCountHelp.Font = $fontNormal
$lnkCountHelp.LinkColor = [System.Drawing.Color]::DeepSkyBlue
$lnkCountHelp.ActiveLinkColor = [System.Drawing.Color]::White
$lnkCountHelp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lnkCountHelp.LinkBehavior = [System.Windows.Forms.LinkBehavior]::NeverUnderline
$lnkCountHelp.Add_Click({
    $msg = if($isTr) { "Sunucunuza eklemek istediğiniz toplam eşzamanlı kullanıcı veya cihaz lisansı sayısıdır. (Örn: 50, 100, 500)" } else { "The total number of concurrent user or device licenses you want to add to your server. (e.g. 50, 100, 500)" }
    Show-CustomMsgBox $msg $script:strings.TitleCount
})
$grpLkp.Controls.Add($lnkCountHelp)

$txtCount = New-Object System.Windows.Forms.TextBox
$txtCount.Location = New-Object System.Drawing.Point(245, 50)
$txtCount.Size = New-Object System.Drawing.Size(100, 25)
$txtCount.Font = $fontNormal
$txtCount.MaxLength = 4
$txtCount.Text = "9999"
$txtCount.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtCount.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtCount.ForeColor = [System.Drawing.Color]::White
$txtCount.ContextMenuStrip = $ctxEditable
$grpLkp.Controls.Add($txtCount)

$lblVer = New-Object System.Windows.Forms.Label
$lblVer.Text = $strings.VerLabel
$lblVer.Location = New-Object System.Drawing.Point(15, 25)
$lblVer.AutoSize = $true
$lblVer.Font = $fontNormal
$lblVer.ForeColor = [System.Drawing.Color]::White
$lblVer.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$grpLkp.Controls.Add($lblVer)

$lnkVerHelp = New-Object System.Windows.Forms.LinkLabel
$lnkVerHelp.Text = "[?]"
$lnkVerHelp.Location = New-Object System.Drawing.Point(210, 25)
$lnkVerHelp.AutoSize = $true
$lnkVerHelp.Font = $fontNormal
$lnkVerHelp.LinkColor = [System.Drawing.Color]::DeepSkyBlue
$lnkVerHelp.ActiveLinkColor = [System.Drawing.Color]::White
$lnkVerHelp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lnkVerHelp.LinkBehavior = [System.Windows.Forms.LinkBehavior]::NeverUnderline
$lnkVerHelp.Add_Click({
    $msg = if($isTr) { "Kullanmakta olduğunuz işletim sistemine uygun RDS sürümüdür.`r`n`r`nPer User: Kullanıcı bazlı (Bağımsız kişi sayısına göre)`r`nPer Device: Cihaz bazlı (Bağlanan makine sayısına göre)" } else { "The RDS version corresponding to your operating system.`r`n`r`nPer User: Based on individual users.`r`nPer Device: Based on connecting machines." }
    Show-CustomMsgBox $msg $script:strings.TitleVer
})
$grpLkp.Controls.Add($lnkVerHelp)

$btnCmbVer = New-Object System.Windows.Forms.Button
$btnCmbVer.Location = New-Object System.Drawing.Point(15, 50)
$btnCmbVer.Size = New-Object System.Drawing.Size(215, 25)
$btnCmbVer.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnCmbVer.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
$btnCmbVer.Font = $fontNormal
$btnCmbVer.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btnCmbVer.ForeColor = [System.Drawing.Color]::White
$btnCmbVer.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$btnCmbVer.Text = "Windows Server 2022 Per User"
$btnCmbVer.Tag = "030_10_2"
$grpLkp.Controls.Add($btnCmbVer)

$ctxVer = New-Object System.Windows.Forms.ContextMenuStrip
$ctxVer.Renderer = $ctxRenderer
$ctxVer.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$ctxVer.ForeColor = [System.Drawing.Color]::White
$ctxVer.ShowImageMargin = $false

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
    $item = $ctxVer.Items.Add($v.Text)
    $item.Tag = $v.Value
    $item.Add_Click({
        param($sender, $e)
        $btnCmbVer.Text = $sender.Text
        $btnCmbVer.Tag = $sender.Tag
    })
}

$btnCmbVer.Add_Click({
    $ctxVer.Show($btnCmbVer, (New-Object System.Drawing.Point(0, $btnCmbVer.Height)))
})

try {
    $osName = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
    $matchedYear = ("2025","2022","2019","2016","2012","2008","2003","2000" | Where-Object { $osName -match $_ }) | Select-Object -First 1
    
    if ($matchedYear) {
        $autoVer = $versions | Where-Object { $_.Text -match $matchedYear } | Sort-Object { $_.Text -notmatch "Per User" } | Select-Object -First 1
        if ($autoVer) {
            $btnCmbVer.Text = $autoVer.Text
            $btnCmbVer.Tag = $autoVer.Value
        }
    }
} catch { }

$btnLkp = New-Object System.Windows.Forms.Button
$btnLkp.Text = $strings.LkpBtn
$btnLkp.Location = New-Object System.Drawing.Point(15, 90)
$btnLkp.Size = New-Object System.Drawing.Size(330, 30)
$btnLkp.Font = $fontNormal
&$styleButton $btnLkp $true
$grpLkp.Controls.Add($btnLkp)

$txtLkpOutput = New-Object System.Windows.Forms.TextBox
$txtLkpOutput.Location = New-Object System.Drawing.Point(15, 130)
$txtLkpOutput.Size = New-Object System.Drawing.Size(290, 50)
$txtLkpOutput.Multiline = $true
$txtLkpOutput.ReadOnly = $true
$txtLkpOutput.Font = New-Object System.Drawing.Font("Consolas", 8, [System.Drawing.FontStyle]::Regular)
$txtLkpOutput.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtLkpOutput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtLkpOutput.ForeColor = [System.Drawing.Color]::White
$txtLkpOutput.ContextMenuStrip = $ctxReadOnly
$grpLkp.Controls.Add($txtLkpOutput)

$btnCopyLkp = New-Object System.Windows.Forms.Button
$btnCopyLkp.Text = [char]::ConvertFromUtf32(0x1F4CB)
$btnCopyLkp.Location = New-Object System.Drawing.Point(315, 140)
$btnCopyLkp.Size = New-Object System.Drawing.Size(30, 30)
$btnCopyLkp.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 10, [System.Drawing.FontStyle]::Regular)
&$styleButton $btnCopyLkp $false
$btnCopyLkp.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($txtLkpOutput.Text)) {
        [System.Windows.Forms.Clipboard]::SetText($txtLkpOutput.Text.Replace("LKP:`r`n", "").Trim())
        Show-CustomMsgBox $script:strings.CopyLkpSuccess $script:strings.InfoTitle
    }
})
$grpLkp.Controls.Add($btnCopyLkp)

$btnSpk.Add_Click({
    $inputPid = $txtPid.Text.Trim()
    if($inputPid -eq "") {
        $txtSpkOutput.Text = $strings.ErrPidReq
        return
    }
    # Auto-format and validate
    $origPid = $inputPid.Trim()
    $blocks = $origPid.Split('-')
    $isLegacyFormat = ($blocks.Length -eq 4 -and $blocks[2].Length -eq 7)

    $cleanPid = $origPid -replace '[\s-]', ''
    if ($cleanPid.Length -eq 20) {
        if ($cleanPid.Substring(5, 3).ToUpper() -eq "OEM") { $isLegacyFormat = $true }

        if ($isLegacyFormat) {
            $inputPid = "{0}-{1}-{2}-{3}" -f $cleanPid.Substring(0,5), $cleanPid.Substring(5,3), $cleanPid.Substring(8,7), $cleanPid.Substring(15,5)
        } else {
            $inputPid = "{0}-{1}-{2}-{3}" -f $cleanPid.Substring(0,5), $cleanPid.Substring(5,5), $cleanPid.Substring(10,5), $cleanPid.Substring(15,5)
        }
        $txtPid.Text = $inputPid
    }

    $baselineRegex = "^([A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5})$|^([A-Za-z0-9]{5}-[A-Za-z0-9]{3}-[A-Za-z0-9]{7}-[A-Za-z0-9]{5})$"
    if ($inputPid -notmatch $baselineRegex) {
        $errMsg = if($script:isTr) { "Hata: Ge$([char]0x00E7)ersiz PID yap$([char]0x0131)s$([char]0x0131). L$([char]0x00FC)tfen standart $([char]0x00FC)r$([char]0x00FC)n anahtar$([char]0x0131) format$([char]0x0131)nda girin (Tireler dahil yakla$([char]0x015F)$([char]0x0131)k 23 karakter, 4 b$([char]0x00F6)l$([char]0x00FC)m)." } else { "Error: Invalid PID structure. Please use a standard format (4 segments separated by dashes)." }
        $txtSpkOutput.Text = $errMsg
        return
    }
    $txtSpkOutput.Text = $strings.Working
    $pattern1 = "^\d{5}-\d{5}-\d{5}-[a-zA-Z]{2}\d{3}$"
    $pattern2 = "^\d{5}-OEM-\d{7}-\d{5}$"
    $pattern3 = "^\d{5}-\d{3}-\d{7}-\d{5}$"
    
    if ($inputPid -notmatch $pattern1 -and $inputPid -notmatch $pattern2 -and $inputPid -notmatch $pattern3) {
        $msg = if($script:isTr) { "Uyar$([char]0x0131): Girdi$([char]0x011F)iniz PID bir Windows Server $([char]0x00FC)r$([char]0x00FC)n$([char]0x00FC)ne ait g$([char]0x00F6)r$([char]0x00FC)nm$([char]0x00FC)yor. Kodlar $([char]0x00FC)retilecek ancak sisteminizde $([char]0x00E7)al$([char]0x0131)$([char]0x015F)mayabilir." } else { "Warning: The entered PID does not appear to belong to a Windows Server product. Codes will be generated but may not work on your system." }
        $txtLogs.Text += "$msg`r`n"
        $scrollThumb.Top = $scrollBg.Height - $scrollThumb.Height - 2
        [System.Windows.Forms.Application]::DoEvents()
    }
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
    # Auto-format and validate
    $origPid = $inputPid.Trim()
    $blocks = $origPid.Split('-')
    $isLegacyFormat = ($blocks.Length -eq 4 -and $blocks[2].Length -eq 7)

    $cleanPid = $origPid -replace '[\s-]', ''
    if ($cleanPid.Length -eq 20) {
        if ($cleanPid.Substring(5, 3).ToUpper() -eq "OEM") { $isLegacyFormat = $true }

        if ($isLegacyFormat) {
            $inputPid = "{0}-{1}-{2}-{3}" -f $cleanPid.Substring(0,5), $cleanPid.Substring(5,3), $cleanPid.Substring(8,7), $cleanPid.Substring(15,5)
        } else {
            $inputPid = "{0}-{1}-{2}-{3}" -f $cleanPid.Substring(0,5), $cleanPid.Substring(5,5), $cleanPid.Substring(10,5), $cleanPid.Substring(15,5)
        }
        $txtPid.Text = $inputPid
    }

    $baselineRegex = "^([A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5})$|^([A-Za-z0-9]{5}-[A-Za-z0-9]{3}-[A-Za-z0-9]{7}-[A-Za-z0-9]{5})$"
    if ($inputPid -notmatch $baselineRegex) {
        $errMsg = if($script:isTr) { "Hata: Ge$([char]0x00E7)ersiz PID yap$([char]0x0131)s$([char]0x0131). L$([char]0x00FC)tfen standart $([char]0x00FC)r$([char]0x00FC)n anahtar$([char]0x0131) format$([char]0x0131)nda girin (Tireler dahil yakla$([char]0x015F)$([char]0x0131)k 23 karakter, 4 b$([char]0x00F6)l$([char]0x00FC)m)." } else { "Error: Invalid PID structure. Please use a standard format (4 segments separated by dashes)." }
        $txtLkpOutput.Text = $errMsg
        return
    }
    $countStr = $txtCount.Text.Trim()
    
    if($inputPid -eq "" -or $countStr -eq "") {
        $txtLkpOutput.Text = $strings.ErrLkpReq
        return
    }
    
    $selVerStr = $btnCmbVer.Tag
    $parts = $selVerStr.Split('_')
    $chid = [int]$parts[0]
    $majorVer = [int]$parts[1]
    $minorVer = [int]$parts[2]
    $countStr = $txtCount.Text.Trim()
    if($countStr -eq "") {
        $count = 0
    } else {
        if (-not ($countStr -match "^\d+$")) {
            $txtLkpOutput.Text = "Hata: Lisans Sayısı kısmına sadece rakam girin."
            return
        }
        $count = [int]$countStr
    }
    if($count -le 0) {
        $txtLkpOutput.Text = "Hata: Lisans Sayısı 0'dan büyük olmalıdır."
        return
    }
    if ($count -gt 9999) {
        $count = 9999
        $txtCount.Text = "9999"
    }

    $pattern1 = "^\d{5}-\d{5}-\d{5}-[a-zA-Z]{2}\d{3}$"
    $pattern2 = "^\d{5}-OEM-\d{7}-\d{5}$"
    $pattern3 = "^\d{5}-\d{3}-\d{7}-\d{5}$"
    
    if ($inputPid -notmatch $pattern1 -and $inputPid -notmatch $pattern2 -and $inputPid -notmatch $pattern3) {
        $msg = if($script:isTr) { "Uyar$([char]0x0131): Girdi$([char]0x011F)iniz PID bir Windows Server $([char]0x00FC)r$([char]0x00FC)n$([char]0x00FC)ne ait g$([char]0x00F6)r$([char]0x00FC)nm$([char]0x00FC)yor. Kodlar $([char]0x00FC)retilecek ancak sisteminizde $([char]0x00E7)al$([char]0x0131)$([char]0x015F)mayabilir." } else { "Warning: The entered PID does not appear to belong to a Windows Server product. Codes will be generated but may not work on your system." }
        $txtLogs.Text += "$msg`r`n"
        $scrollThumb.Top = $scrollBg.Height - $scrollThumb.Height - 2
        [System.Windows.Forms.Application]::DoEvents()
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

$txtLogs = New-Object System.Windows.Forms.TextBox
$txtLogs.Location = New-Object System.Drawing.Point(15, 435)
$txtLogs.Size = New-Object System.Drawing.Size(345, 95)
$txtLogs.Multiline = $true
$txtLogs.ScrollBars = [System.Windows.Forms.ScrollBars]::None
$txtLogs.ReadOnly = $true
$txtLogs.Font = New-Object System.Drawing.Font("Consolas", 8, [System.Drawing.FontStyle]::Regular)
$txtLogs.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtLogs.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$txtLogs.ForeColor = [System.Drawing.Color]::Lime
if($script:isTr) { $txtLogs.Text = "RDS Gen Sistem Logları...`r`n" } else { $txtLogs.Text = "RDS Gen System Logs...`r`n" }
$mainPanel.Controls.Add($txtLogs)

$scrollBg = New-Object System.Windows.Forms.Panel
$scrollBg.Size = New-Object System.Drawing.Size(15, 95)
$scrollBg.Location = New-Object System.Drawing.Point(360, 435)
$scrollBg.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
$scrollBg.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

$scrollThumb = New-Object System.Windows.Forms.Panel
$scrollThumb.Size = New-Object System.Drawing.Size(13, 30)
$scrollThumb.Location = New-Object System.Drawing.Point(0, 0)
$scrollThumb.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
$scrollThumb.Cursor = [System.Windows.Forms.Cursors]::Hand
$scrollThumb.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(95, 95, 100) })
$scrollThumb.Add_MouseLeave({ if (-not $script:isDraggingThumb) { $this.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80) } })

$script:isDraggingThumb = $false
$script:thumbStartY = 0
$scrollThumb.Add_MouseDown({
    param($sender, $e)
    $script:isDraggingThumb = $true
    $script:thumbStartY = $e.Y
    $sender.BackColor = [System.Drawing.Color]::FromArgb(110, 110, 115)
})
$scrollThumb.Add_MouseUp({
    $script:isDraggingThumb = $false
    $scrollThumb.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 80)
})

$scrollThumb.Add_MouseMove({
    param($sender, $e)
    if ($script:isDraggingThumb) {
        $newY = $sender.Top + $e.Y - $script:thumbStartY
        if ($newY -lt 0) { $newY = 0 }
        $maxY = $scrollBg.Height - $sender.Height - 2
        if ($newY -gt $maxY) { $newY = $maxY }
        $sender.Top = $newY
        
        $pct = $newY / $maxY
        $totalLines = $txtLogs.Lines.Count
        $visibleLines = 6
        if ($totalLines -gt $visibleLines) {
            $maxScroll = $totalLines - $visibleLines
            $targetLine = [int][math]::Round($pct * $maxScroll)
            
            $EM_GETFIRSTVISIBLELINE = 0x00CE
            $EM_LINESCROLL = 0x00B6
            
            $currentLine = [Win32Scroll]::SendMessage($txtLogs.Handle, $EM_GETFIRSTVISIBLELINE, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
            $delta = $targetLine - $currentLine
            if ($delta -ne 0) {
                [Win32Scroll]::SendMessage($txtLogs.Handle, $EM_LINESCROLL, [IntPtr]::Zero, [IntPtr]$delta) | Out-Null
            }
        }
    }
})

$txtLogs.Add_MouseWheel({
    param($sender, $e)
    $totalLines = $txtLogs.Lines.Count
    $visibleLines = 6
    if ($totalLines -gt $visibleLines) {
        $EM_GETFIRSTVISIBLELINE = 0x00CE
        $currentLine = [Win32Scroll]::SendMessage($txtLogs.Handle, $EM_GETFIRSTVISIBLELINE, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
        
        $linesToScroll = -($e.Delta / 120) * 3
        $newLine = $currentLine + $linesToScroll
        if ($newLine -lt 0) { $newLine = 0 }
        $maxScroll = $totalLines - $visibleLines
        if ($newLine -gt $maxScroll) { $newLine = $maxScroll }
        
        $delta = $newLine - $currentLine
        if ($delta -ne 0) {
            $EM_LINESCROLL = 0x00B6
            [Win32Scroll]::SendMessage($txtLogs.Handle, $EM_LINESCROLL, [IntPtr]::Zero, [IntPtr]$delta) | Out-Null
            
            $pct = $newLine / $maxScroll
            $maxY = $scrollBg.Height - $scrollThumb.Height - 2
            $scrollThumb.Top = [math]::Round($pct * $maxY)
        }
    }
})

$scrollBg.Controls.Add($scrollThumb)
$mainPanel.Controls.Add($scrollBg)

$btnSave = New-Object System.Windows.Forms.Button
if($isTr) { $btnSave.Text = "Kaydet" } else { $btnSave.Text = "Save" }
$btnSave.Location = New-Object System.Drawing.Point(15, 540)
$btnSave.Size = New-Object System.Drawing.Size(90, 30)
$btnSave.Font = $fontNormal
&$styleButton $btnSave $false
$btnSave.Add_Click({
    $spkText = $txtSpkOutput.Text.Replace("SPK:`r`n", "").Trim()
    $lkpText = $txtLkpOutput.Text.Replace("LKP:`r`n", "").Trim()
    $pidText = $txtPid.Text.Trim()
    $countText = $txtCount.Text.Trim()
    $verText = $btnCmbVer.Text

    if ([string]::IsNullOrWhiteSpace($spkText) -and [string]::IsNullOrWhiteSpace($lkpText)) {
        Show-CustomMsgBox $script:strings.ErrNoSave $script:strings.WarningTitle
        return
    }

    $baseDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($baseDir)) { $baseDir = [Environment]::GetFolderPath("Desktop") }
    $fileName = if ($script:isTr) { "RDS_Lisans_Kayitlari.txt" } else { "RDS_License_Records.txt" }
    $filePath = Join-Path -Path $baseDir -ChildPath $fileName
    $dateStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($script:isTr) {
        $report = "----------------------------------------`r`n" +
                  "Tarih: $dateStr`r`n" +
                  "Product ID: $pidText`r`n" +
                  "S$([char]0x00FC)r$([char]0x00FC)m: $verText`r`n" +
                  "Lisans Say$([char]0x0131)s$([char]0x0131): $countText`r`n`r`n" +
                  "$([char]0x00DC)retilen SPK:`r`n$spkText`r`n`r`n" +
                  "$([char]0x00DC)retilen LKP:`r`n$lkpText`r`n" +
                  "----------------------------------------"
    } else {
        $report = "----------------------------------------`r`n" +
                  "Date: $dateStr`r`n" +
                  "Product ID: $pidText`r`n" +
                  "Version: $verText`r`n" +
                  "License Count: $countText`r`n`r`n" +
                  "Generated SPK:`r`n$spkText`r`n`r`n" +
                  "Generated LKP:`r`n$lkpText`r`n" +
                  "----------------------------------------"
    }
    
    try {
        Add-Content -Path $filePath -Value $report -Encoding UTF8
        Show-CustomMsgBox "$($script:strings.SaveSuccess)$filePath" $script:strings.SuccessTitle
    } catch {
        Show-CustomMsgBox "$($script:strings.SaveError)$($_.Exception.Message)" $script:strings.ErrorTitle
    }
})
$mainPanel.Controls.Add($btnSave)

$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Text = [char]::ConvertFromUtf32(0x21BB)
$btnReset.Location = New-Object System.Drawing.Point(115, 540)
$btnReset.Size = New-Object System.Drawing.Size(30, 30)
$btnReset.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 12, [System.Drawing.FontStyle]::Bold)
$btnReset.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnReset.FlatAppearance.BorderSize = 1
$btnReset.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 60, 65)
$btnReset.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$btnReset.ForeColor = [System.Drawing.Color]::White
$btnReset.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnReset.Add_MouseEnter({ $btnReset.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50) })
$btnReset.Add_MouseLeave({ $btnReset.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) })
$btnReset.Add_Click({
    $txtPid.Text = ""
    $txtCount.Text = "1"
    if($isTr) { $btnCmbVer.Text = "  Windows Server 2022 / 2025" } else { $btnCmbVer.Text = "  Windows Server 2022 / 2025" }
    $btnCmbVer.Tag = 0
    $txtSpkOutput.Text = ""
    $txtLkpOutput.Text = ""
    $txtSpkOutput.ForeColor = [System.Drawing.Color]::White
    $txtLkpOutput.ForeColor = [System.Drawing.Color]::White
    if($script:isTr) { $txtLogs.Text = "RDS Gen Sistem Logları...`r`n" } else { $txtLogs.Text = "RDS Gen System Logs...`r`n" }
    $scrollThumb.Top = 0
})
$mainPanel.Controls.Add($btnReset)

$btnSettings = New-Object System.Windows.Forms.Button
$btnSettings.Text = [char]::ConvertFromUtf32(0x2699)
$btnSettings.Location = New-Object System.Drawing.Point(155, 540)
$btnSettings.Size = New-Object System.Drawing.Size(30, 30)
$btnSettings.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 12, [System.Drawing.FontStyle]::Regular)
$btnSettings.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnSettings.FlatAppearance.BorderSize = 1
$btnSettings.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 60, 65)
$btnSettings.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$btnSettings.ForeColor = [System.Drawing.Color]::White
$btnSettings.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnSettings.Add_MouseEnter({ $btnSettings.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 70) })
$btnSettings.Add_MouseLeave({ $btnSettings.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) })

$ctxSettings = New-Object System.Windows.Forms.ContextMenuStrip
$ctxSettings.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$ctxSettings.ForeColor = [System.Drawing.Color]::White
$ctxSettings.ShowImageMargin = $false
$script:iPhase1 = $ctxSettings.Items.Add($script:strings.Phase1)
$script:iPhase2 = $ctxSettings.Items.Add($script:strings.Phase2)

$script:iPhase1.Add_Click({
    $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
    if (-not $isServer) {
        $warnMsg = if($script:isTr) { "Bu işlem sadece Windows Server sürümlerinde desteklenmektedir!`r`nMevcut işletim sisteminiz bir Server sürümü değil." } else { "This operation is only supported on Windows Server editions!`r`nYour current OS is not a Server edition." }
        Show-CustomMsgBox $warnMsg $script:strings.WarningTitle
        return
    }
    $res = Show-CustomMsgBox $script:strings.Phase1Msg $script:strings.WarningTitle "YesNo"
    if ($res -eq "Yes") {
        if($script:isTr) { $txtLogs.Text += "Adım 1 harici konsola aktarıldı. Lütfen işlemleri açılan konsol ekranından takip edin.`r`n" } else { $txtLogs.Text += "Phase 1 sent to external console. Please follow the process from the opened console screen.`r`n" }
        $scrollThumb.Top = $scrollBg.Height - $scrollThumb.Height - 2
        [System.Windows.Forms.Application]::DoEvents()
        
        $tmpScript = "$env:TEMP\rds_uninstall.ps1"
        $scriptContent = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$host.UI.RawUI.WindowTitle = if(`$$($script:isTr)) { 'RDS Kaldirma (Adim 1)' } else { 'RDS Uninstall (Phase 1)' }
if(`$$($script:isTr)) { Write-Host "`n[Adım 1] TermServLicensing servisi durduruluyor..." -ForegroundColor Cyan } else { Write-Host "`n[Phase 1] Stopping TermServLicensing service..." -ForegroundColor Cyan }
Stop-Service TermServLicensing -Force
taskkill /F /FI `"SERVICES eq TermServLicensing`" 2>`$null
Start-Sleep -Seconds 2

if(`$$($script:isTr)) { Write-Host "`n[Adım 1] Kalıntılar temizleniyor..." -ForegroundColor Cyan } else { Write-Host "`n[Phase 1] Cleaning up leftovers..." -ForegroundColor Cyan }
Remove-Item `"C:\Windows\System32\lserver`" -Recurse -Force
reg delete `"HKLM\SOFTWARE\Microsoft\TermServLicensing`" /f 2>`$null
reg delete `"HKLM\SYSTEM\CurrentControlSet\Services\TermServLicensing`" /f 2>`$null

if(`$$($script:isTr)) { Write-Host "`n[Adım 1] RDS Lisanslama rolü kaldırılıyor. Lütfen bekleyin (bu işlem biraz sürebilir)..." -ForegroundColor Cyan } else { Write-Host "`n[Phase 1] Uninstalling RDS Licensing role. Please wait (this might take a while)..." -ForegroundColor Cyan }
`$ErrorActionPreference = 'Continue'
Uninstall-WindowsFeature -Name RDS-Licensing

Write-Host "`n-----------------------------------------------------" -ForegroundColor Yellow
if(`$$($script:isTr)) { Write-Host "İşlemler başarıyla tamamlandı!" -ForegroundColor Green } else { Write-Host "Operations completed successfully!" -ForegroundColor Green }
if(`$$($script:isTr)) { Write-Host "Değişikliklerin etkili olması için sunucuyu YENİDEN BAŞLATIN." -ForegroundColor Red } else { Write-Host "RESTART the server for changes to take effect." -ForegroundColor Red }
Write-Host "-----------------------------------------------------" -ForegroundColor Yellow

if(`$$($script:isTr)) { Write-Host "`nPencereyi kapatmak için ENTER tuşuna basın..." -ForegroundColor Magenta } else { Write-Host "`nPress ENTER to close this window..." -ForegroundColor Magenta }
Read-Host
Remove-Item -Path "`$PSCommandPath" -Force
"@
        [System.IO.File]::WriteAllText($tmpScript, $scriptContent, [System.Text.Encoding]::UTF8)
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript`"" -Verb RunAs
    }
})

$script:iPhase2.Add_Click({
    $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
    if (-not $isServer) {
        $warnMsg = if($script:isTr) { "Bu işlem sadece Windows Server sürümlerinde desteklenmektedir!`r`nMevcut işletim sisteminiz bir Server sürümü değil." } else { "This operation is only supported on Windows Server editions!`r`nYour current OS is not a Server edition." }
        Show-CustomMsgBox $warnMsg $script:strings.WarningTitle
        return
    }
    $res = Show-CustomMsgBox $script:strings.Phase2Msg $script:strings.InfoTitle "YesNo"
    if ($res -eq "Yes") {
        if($script:isTr) { $txtLogs.Text += "Adım 2 harici konsola aktarıldı. Lütfen işlemleri açılan konsol ekranından takip edin.`r`n" } else { $txtLogs.Text += "Phase 2 sent to external console. Please follow the process from the opened console screen.`r`n" }
        $scrollThumb.Top = $scrollBg.Height - $scrollThumb.Height - 2
        [System.Windows.Forms.Application]::DoEvents()
        
        $tmpScript2 = "$env:TEMP\rds_install.ps1"
        $scriptContent2 = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$host.UI.RawUI.WindowTitle = if(`$$($script:isTr)) { 'RDS Kurulum (Adim 2)' } else { 'RDS Install (Phase 2)' }
if(`$$($script:isTr)) { Write-Host "`n[Adım 2] RDS Lisanslama rolü kuruluyor. Lütfen bekleyin..." -ForegroundColor Cyan } else { Write-Host "`n[Phase 2] Installing RDS Licensing role. Please wait..." -ForegroundColor Cyan }
`$ErrorActionPreference = 'Continue'
Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools

`$ErrorActionPreference = 'SilentlyContinue'
if(`$$($script:isTr)) { Write-Host "`n[Adım 2] Servis başlatılıyor..." -ForegroundColor Cyan } else { Write-Host "`n[Phase 2] Starting service..." -ForegroundColor Cyan }
Start-Service TermServLicensing

Write-Host "`n-----------------------------------------------------" -ForegroundColor Yellow
if(`$$($script:isTr)) { Write-Host "Kurulum başarıyla tamamlandı!" -ForegroundColor Green } else { Write-Host "Installation completed successfully!" -ForegroundColor Green }
Write-Host "-----------------------------------------------------" -ForegroundColor Yellow

if(`$$($script:isTr)) { Write-Host "`nPencereyi kapatmak için ENTER tuşuna basın..." -ForegroundColor Magenta } else { Write-Host "`nPress ENTER to close this window..." -ForegroundColor Magenta }
Read-Host
Remove-Item -Path "`$PSCommandPath" -Force
"@
        [System.IO.File]::WriteAllText($tmpScript2, $scriptContent2, [System.Text.Encoding]::UTF8)
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript2`"" -Verb RunAs
    }
})

$btnSettings.Add_Click({
    $ctxSettings.Show($btnSettings, (New-Object System.Drawing.Point(0, -$ctxSettings.Height)))
})
$mainPanel.Controls.Add($btnSettings)

$btnAbout = New-Object System.Windows.Forms.Button
$btnAbout.Text = $strings.AboutBtn
$btnAbout.Location = New-Object System.Drawing.Point(195, 540)
$btnAbout.Size = New-Object System.Drawing.Size(85, 30)
$btnAbout.Font = $fontNormal
&$styleButton $btnAbout $false
$btnAbout.Add_Click({
    $aboutForm = New-Object System.Windows.Forms.Form
    $aboutForm.Text = $strings.AboutTitle
    $aboutForm.Size = New-Object System.Drawing.Size(390, 250)
    $aboutForm.StartPosition = "CenterParent"
    $aboutForm.FormBorderStyle = "None"
    $aboutForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $aboutForm.Opacity = 0
    $aboutForm.KeyPreview = $true
    $aboutForm.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape -or $e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $aboutForm.Close()
        }
    })
    $aboutForm.Add_Load({
        $script:fadeTimerAbt = New-Object System.Windows.Forms.Timer
        $script:fadeTimerAbt.Interval = 10
        $script:fadeTimerAbt.Add_Tick({
            $aboutForm.Opacity += 0.1
            if ($aboutForm.Opacity -ge 1) {
                $script:fadeTimerAbt.Stop()
                $script:fadeTimerAbt.Dispose()
            }
        })
        $script:fadeTimerAbt.Start()
    })

    $aboutForm.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::Gray, 1)
        $e.Graphics.DrawRectangle($pen, 0, 0, ($aboutForm.Width - 1), ($aboutForm.Height - 1))
    })

    $aboutTitleBar = New-Object System.Windows.Forms.Panel
    $aboutTitleBar.Height = 30
    $aboutTitleBar.Dock = [System.Windows.Forms.DockStyle]::Top
    $aboutTitleBar.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $aboutTitleLbl = New-Object System.Windows.Forms.Label
    $aboutTitleLbl.Text = $strings.AboutTitle
    $aboutTitleLbl.Location = New-Object System.Drawing.Point(10, 5)
    $aboutTitleLbl.AutoSize = $true
    $aboutTitleLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $aboutTitleLbl.ForeColor = [System.Drawing.Color]::White
    $aboutTitleLbl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $aboutTitleBar.Controls.Add($aboutTitleLbl)

    $aboutTitleBar.Add_MouseDown($dragAction)
    $aboutTitleBar.Add_MouseMove($moveAction)
    $aboutTitleBar.Add_MouseUp($upAction)
    $aboutTitleBar.Add_Click({ $aboutForm.Close() })
    $aboutTitleLbl.Add_MouseDown($dragAction)
    $aboutTitleLbl.Add_MouseMove($moveAction)
    $aboutTitleLbl.Add_MouseUp($upAction)
    $aboutTitleLbl.Add_Click({ $aboutForm.Close() })

    $aboutForm.Controls.Add($aboutTitleBar)

    $aboutMainPanel = New-Object System.Windows.Forms.Panel
    $aboutMainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $aboutMainPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $aboutForm.Controls.Add($aboutMainPanel)
    $aboutMainPanel.BringToFront()

    $lblLine1 = New-Object System.Windows.Forms.Label
    $lblLine1.Text = "Coded by Abdullah ERTÜRK"
    $lblLine1.Location = New-Object System.Drawing.Point(20, 20)
    $lblLine1.AutoSize = $true
    $lblLine1.Font = $fontBold
    $lblLine1.ForeColor = [System.Drawing.Color]::White
    $lblLine1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $lblLine1.Add_Click({ $aboutForm.Close() })
    $aboutMainPanel.Controls.Add($lblLine1)
    $aboutMainPanel.Add_Click({ $aboutForm.Close() })

    $lnkGitHub = New-Object System.Windows.Forms.LinkLabel
    $lnkGitHub.Text = "github.com/abdullah-erturk"
    $lnkGitHub.Location = New-Object System.Drawing.Point(20, 50)
    $lnkGitHub.AutoSize = $true
    $lnkGitHub.Font = $fontNormal
    $lnkGitHub.LinkColor = [System.Drawing.Color]::FromArgb(78, 179, 211)
    $lnkGitHub.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $lnkGitHub.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://github.com/abdullah-erturk") | Out-Null })
    $aboutMainPanel.Controls.Add($lnkGitHub)

    $lnkWeb = New-Object System.Windows.Forms.LinkLabel
    $lnkWeb.Text = "erturk-dev.netlify.app"
    $lnkWeb.Location = New-Object System.Drawing.Point(20, 75)
    $lnkWeb.AutoSize = $true
    $lnkWeb.Font = $fontNormal
    $lnkWeb.LinkColor = [System.Drawing.Color]::FromArgb(78, 179, 211)
    $lnkWeb.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $lnkWeb.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://erturk-dev.netlify.app") | Out-Null })
    $aboutMainPanel.Controls.Add($lnkWeb)

    $lnkThanks = New-Object System.Windows.Forms.LinkLabel
    if($isTr) { $lnkThanks.Text = "Teşekkürler WitherOrNot, Lyssa (thecatontheceiling) ve Bensuslu11" } else { $lnkThanks.Text = "Thanks to WitherOrNot, Lyssa (thecatontheceiling) and Bensuslu11" }
    $lnkThanks.Location = New-Object System.Drawing.Point(20, 115)
    $lnkThanks.AutoSize = $true
    $lnkThanks.Font = $fontNormal
    $lnkThanks.LinkColor = [System.Drawing.Color]::FromArgb(78, 179, 211)
    $lnkThanks.ForeColor = [System.Drawing.Color]::White
    $lnkThanks.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $lnkThanks.LinkArea = New-Object System.Windows.Forms.LinkArea(0, 0)
    
    $witherStart = $lnkThanks.Text.IndexOf("WitherOrNot")
    [void]$lnkThanks.Links.Add($witherStart, 11, "https://github.com/WitherOrNot")
    
    $lyssaStart = $lnkThanks.Text.IndexOf("Lyssa")
    [void]$lnkThanks.Links.Add($lyssaStart, 26, "https://github.com/thecatontheceiling")

    $bensuStart = $lnkThanks.Text.IndexOf("Bensuslu11")
    [void]$lnkThanks.Links.Add($bensuStart, 10, "https://github.com/Bensuslu11")
    
    $lnkThanks.Add_LinkClicked({
        param($sender, $e)
        [System.Diagnostics.Process]::Start($e.Link.LinkData) | Out-Null
    })
    $aboutMainPanel.Controls.Add($lnkThanks)

    $ipAddr = "Bilinmiyor"
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        if ($ips) { $ipAddr = $ips[0].ToString() }
    } catch {}

    $lblHost = New-Object System.Windows.Forms.Label
    $lblHost.Text = "Host: $env:COMPUTERNAME  |  IP: $ipAddr"
    $lblHost.Location = New-Object System.Drawing.Point(20, 150)
    $lblHost.AutoSize = $true
    $lblHost.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Regular)
    $lblHost.ForeColor = [System.Drawing.Color]::DarkGray
    $lblHost.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $lblHost.Add_Click({ $aboutForm.Close() })
    $aboutMainPanel.Controls.Add($lblHost)

    $btnAboutClose = New-Object System.Windows.Forms.Button
    $btnAboutClose.Text = "Kapat"
    $btnAboutClose.Location = New-Object System.Drawing.Point(275, 175)
    $btnAboutClose.Size = New-Object System.Drawing.Size(100, 30)
    $btnAboutClose.Font = $fontNormal
    &$styleButton $btnAboutClose $false
    $btnAboutClose.Add_Click({ $aboutForm.Close() })
    $aboutMainPanel.Controls.Add($btnAboutClose)

    $aboutForm.ShowDialog() | Out-Null
})
$mainPanel.Controls.Add($btnAbout)

$btnHelp = New-Object System.Windows.Forms.Button
$btnHelp.Text = $strings.HelpBtn
$btnHelp.Location = New-Object System.Drawing.Point(290, 540)
$btnHelp.Size = New-Object System.Drawing.Size(85, 30)
$btnHelp.Font = $fontNormal
&$styleButton $btnHelp $false
$btnHelp.Add_Click({
    Show-CustomMsgBox $strings.HelpText $strings.HelpTitle
})
$mainPanel.Controls.Add($btnHelp)

$form.KeyPreview = $true
$form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        $form.Close()
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::S) {
        $btnSave.PerformClick()
    }
    elseif ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        if ($txtPid.Focused) {
            $btnSpk.PerformClick()
            $e.SuppressKeyPress = $true
        } elseif ($txtCount.Focused) {
            $btnLkp.PerformClick()
            $e.SuppressKeyPress = $true
        }
    }
})

$form.ShowDialog() | Out-Null
