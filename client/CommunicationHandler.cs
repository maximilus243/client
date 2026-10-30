using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace client
{
    /// <summary>
    /// מחלקה המנהלת את התקשורת של הלקוח מול השרת ברמת הרשת (TCP Socket):
    /// מטפלת בהתחברות, ניהול זיכרון חוצץ (Buffer), לחיצת יד מוצפנת (RSA/AES),
    /// רוטציית מפתחות תקופתית, והצפנה/פענוח שקופים של הודעות.
    /// </summary>
    public class CommunicationHandler
    {
        private TcpClient client;
        private NetworkStream ns;
        private byte[] data = new byte[8192];
        private StringBuilder _incomingBuffer = new StringBuilder();
        private string Server_Ip = "127.0.0.1";
        private int portNo = 1500;

        // --- משתני הצפנה וניהול סשן ---
        private string _serverPublicKeyXml;
        private System.Threading.Timer _keyRotationTimer;
        private byte[] _aesKey;
        private byte[] _aesIV;
        private byte[] _nextAesKey;
        private byte[] _nextAesIV;
        private bool _isHandshakeComplete = false;

        /// <summary>
        /// אירוע (Event) המופעל בכל פעם שמתקבלת הודעה מפוענחת ותקינה מהשרת.
        /// </summary>
        public event Action<string> OnMessageReceived;

        /// <summary>
        /// בנאי המחלקה - מנסה להתחבר לשרת בכתובת והפורט המוגדרים ומפעיל האזנה אסינכרונית לתקשורת נכנסת.
        /// </summary>
        public CommunicationHandler()
        {
            try
            {
                client = new TcpClient(Server_Ip, portNo);
                ns = client.GetStream();
                // התחלת האזנה אסינכרונית לקבלת נתונים מהשרת
                ns.BeginRead(data, 0, data.Length, ReceiveCallback, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Connection to server failed: " + ex.Message);
            }
        }

        /// <summary>
        /// מתודת קריאה חוזרת (Callback) לקבלת נתונים מה-Socket, הוספתם לחוצץ והמשך האזנה.
        /// </summary>
        /// <param name="ar">תוצאת הפעולה האסינכרונית.</param>
        private void ReceiveCallback(IAsyncResult ar)
        {
            try
            {
                int bytesRead = ns.EndRead(ar);

                if (bytesRead > 0)
                {
                    // 1. המרת הבייטים הנכנסים למחרוזת והוספתם לחוצץ הצבירה (Buffer)
                    string chunk = Encoding.UTF8.GetString(data, 0, bytesRead);
                    _incomingBuffer.Append(chunk);

                    // 2. עיבוד החוצץ וחילוץ שורות שלמות (המופרדות ב-'\n')
                    ProcessBuffer();

                    // 3. המשך האזנה לחבילות מידע נוספות
                    ns.BeginRead(data, 0, data.Length, ReceiveCallback, null);
                }
                else
                {
                    // קריאת 0 בייטים מצביעה על ניתוק מהשרת
                    Disconnect();
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Disconnected from server.");
                Disconnect();
            }
        }

        /// <summary>
        /// מעבדת את החוצץ (Buffer) ומפרקת אותו להודעות בודדות המופרדות בתו שורה חדשה ('\n').
        /// </summary>
        private void ProcessBuffer()
        {
            string currentData = _incomingBuffer.ToString();
            int newlineIndex;

            // חיפוש הופעות של שורה חדשה כדי לטפל בחבילות שהגיעו בצורה מקוטעת או מחוברת
            while ((newlineIndex = currentData.IndexOf('\n')) >= 0)
            {
                string line = currentData.Substring(0, newlineIndex).Trim('\r', '\n', ' ');

                // הסרת השורה שכבר עובדה מתוך החוצץ
                currentData = currentData.Substring(newlineIndex + 1);
                _incomingBuffer.Clear();
                _incomingBuffer.Append(currentData);

                if (!string.IsNullOrEmpty(line))
                {
                    HandleSinglePacket(line);
                }
            }
        }

        /// <summary>
        /// מטפלת בהודעה בודדת שחולצה מהחוצץ: ניהול מפתחות RSA/AES, אישור לחיצת יד, או פענוח והעברה לממשק.
        /// </summary>
        /// <param name="response">הודעת הטקסט שחולצה מהחוצץ.</param>
        private void HandleSinglePacket(string response)
        {
            // טיפול בקבלת מפתח RSA ציבורי מהשרת
            if (response.StartsWith("#RSA_KEY"))
            {
                _serverPublicKeyXml = response.Substring("#RSA_KEY".Length).Trim();
                GenerateAndSendAesKey();

                // איפוס הטיימר להחלת רוטציית מפתחות AES תקופתית
                if (_keyRotationTimer != null)
                {
                    _keyRotationTimer.Dispose();
                }

                // יצירת טיימר לרוטציית מפתחות (מתחיל לאחר 300 שניות, ומורץ כל 30 שניות)
                _keyRotationTimer = new System.Threading.Timer(_ => GenerateAndSendAesKey(), null, TimeSpan.FromSeconds(300), TimeSpan.FromSeconds(30));
            }
            // אישור לחיצת יד / עדכון מפתח AES מהשרת
            else if (response.StartsWith("#HANDSHAKE_OK"))
            {
                if (_nextAesKey != null && _nextAesIV != null)
                {
                    _aesKey = _nextAesKey;
                    _aesIV = _nextAesIV;
                    _nextAesKey = null;
                    _nextAesIV = null;
                }

                _isHandshakeComplete = true;
                Console.WriteLine("AES Key exchange / rotation verified by server.");
            }
            // טיפול בהודעת פקודת תפוגת זמן סשן
            else if (response.StartsWith("SESSION_EXPIRED"))
            {
                Console.WriteLine("Session expired by server.");
                OnMessageReceived?.Invoke("SESSION_EXPIRED");
                Disconnect();
            }
            // הודעה רגילה מהשרת - פענוח במידת הצורך והפעלת אירוע קבלת הודעה
            else
            {
                string decryptedResponse = response;
                if (_isHandshakeComplete)
                {
                    try
                    {
                        decryptedResponse = DecryptMessage(response);
                    }
                    catch
                    {
                        // ברירת מחדל במקרה שהטקסט הגיע כטקסט גלוי (Plain Text)
                        decryptedResponse = response;
                    }
                }
                OnMessageReceived?.Invoke(decryptedResponse);
            }
        }

        /// <summary>
        /// מייצרת מפתח AES וויקטור אתחול (IV) חדשים, מצפינה אותם באמצעות המפתח הציבורי של ה-RSA ושולחת לשרת.
        /// </summary>
        private void GenerateAndSendAesKey()
        {
            try
            {
                if (string.IsNullOrEmpty(_serverPublicKeyXml)) return;

                // 1. יצירת מפתח AES ו-IV חדשים
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();

                    _nextAesKey = aes.Key;
                    _nextAesIV = aes.IV;
                }

                // 2. הצפנת המפתח וה-IV באמצעות מפתח ה-RSA הציבורי של השרת
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(_serverPublicKeyXml);

                    byte[] encryptedKey = rsa.Encrypt(_nextAesKey, RSAEncryptionPadding.OaepSHA256);
                    byte[] encryptedIV = rsa.Encrypt(_nextAesIV, RSAEncryptionPadding.OaepSHA256);

                    string keyBase64 = Convert.ToBase64String(encryptedKey);
                    string ivBase64 = Convert.ToBase64String(encryptedIV);

                    // 3. שליחת המפתחות המוצפנים בפורמט Base64 לשרת
                    SendMessage($"#AES_KEY {keyBase64} {ivBase64}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error during AES Key Generation: " + ex.Message);
            }
        }

        /// <summary>
        /// שולחת הודעת טקסט לשרת. מצפינה אותה ב-AES במידה ותהליך לחיצת היד הושלם.
        /// </summary>
        /// <param name="msg">הודעת הטקסט לשליחה.</param>
        public void SendMessage(string msg)
        {
            try
            {
                if (ns != null && client != null && client.Connected)
                {
                    string messageToSend = _isHandshakeComplete ? EncryptMessage(msg) : msg;
                    byte[] byteMsg = Encoding.UTF8.GetBytes(messageToSend + "\n");
                    ns.Write(byteMsg, 0, byteMsg.Length);
                    ns.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending message: " + ex.Message);
            }
        }

        /// <summary>
        /// סוגרת את חיבור ה-Socket, משחררת את משאבי הטיימר וה-NetworkStream.
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (_keyRotationTimer != null)
                {
                    _keyRotationTimer.Dispose();
                    _keyRotationTimer = null;
                }

                if (ns != null) ns.Close();
                if (client != null) client.Close();
            }
            catch { }
        }

        /// <summary>
        /// מצפינה מחרוזת טקסט גלוי באמצעות מפתח ה-AES וה-IV הפעילים של הסשן.
        /// </summary>
        /// <param name="plainText">הטקסט להצפנה.</param>
        /// <returns>מחרוזת מוצפנת בפורמט Base64.</returns>
        public string EncryptMessage(string plainText)
        {
            if (!_isHandshakeComplete) return plainText;

            using (Aes aes = Aes.Create())
            {
                aes.Key = _aesKey;
                aes.IV = _aesIV;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(inputBytes, 0, inputBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        /// <summary>
        /// מפענחת מחרוזת מוצפנת בפורמט Base64 באמצעות מפתח ה-AES וה-IV הפעילים.
        /// </summary>
        /// <param name="cipherTextBase64">הטקסט המוצפן בפורמט Base64.</param>
        /// <returns>מחרוזת הטקסט המקורית המפוענחת.</returns>
        public string DecryptMessage(string cipherTextBase64)
        {
            if (!_isHandshakeComplete) return cipherTextBase64;

            byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
            using (Aes aes = Aes.Create())
            {
                aes.Key = _aesKey;
                aes.IV = _aesIV;

                using (MemoryStream ms = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}