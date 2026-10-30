using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace client
{
    /// <summary>
    /// הטופס המרכזי של הלקוח (Form1) המנהל את ממשק המשתמש עבור התחברות, הרשמה, אימות CAPTCHA ואימות קוד OTP.
    /// </summary>
    public partial class RegisterForm : Form
    {
        private CommunicationHandler CH;
        private string _currentUsername = "";
        private Form _captchaDialog;

        /// <summary>
        /// בנאי הטופס - מאתחל את רכיבי ממשק המשתמש, את מנהל התקשורת ונרשם לאירוע קבלת הודעות מהשרת.
        /// </summary>
        public RegisterForm()
        {
            InitializeComponent();
            CH = new CommunicationHandler();
            CH.OnMessageReceived += ProcessServerMessage;
            this.FormClosing += Form1_FormClosing;
        }

        /// <summary>
        /// מנהל את עיבוד ההודעות המתקבלות מהשרת ומעדכן את ממשק המשתמש בהתאם.
        /// כולל סנכרון תהליכונים (Thread Sync) באמצעות BeginInvoke כדי למנוע נעילה של ממשק המשתמש.
        /// </summary>
        /// <param name="response">ההודעה שהתקבלה מהשרת.</param>
        private void ProcessServerMessage(string response)
        {
            // בדיקה האם יש צורך לבצע סנכרון לתהליכון של ה-UI
            if (this.IsDisposed || !this.IsHandleCreated) return;

            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => ProcessServerMessage(response)));
                return;
            }

            // טיפול במקרה של תפוגת זמן סשן (Session Timeout)
            if (response == "SESSION_EXPIRED")
            {
                MessageBox.Show("Connection ended due to Session Timeout.", "Disconnected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                CH.OnMessageReceived -= ProcessServerMessage;
                CH.Disconnect();
                Application.Exit();
                return;
            }
            else if (response.StartsWith("AssignPlayer"))
            {
                // Extract player ID (e.g., "1")
                string playerId = response.Contains("#") ? response.Split('#')[1] : "";

                // Unsubscribe from login events
                CH.OnMessageReceived -= ProcessServerMessage;

                // Hide login form silently
                this.Hide();

                // Pass the assigned ID directly to your game/lobby form
                // FormGame game = new FormGame(playerId);
                // game.Show();
            }
            // קבלת תמונת CAPTCHA מהשרת והצגתה
            else if (response.StartsWith("#CAPTCHA_IMAGE"))
            {
                try
                {
                    string base64Image = response.Substring("#CAPTCHA_IMAGE".Length).Trim();
                    DisplayCaptchaWindow(base64Image);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Failed to load CAPTCHA image: " + ex.Message);
                }
            }
            // אישור שה-CAPTCHA נפתר בהצלחה
            else if (response == "CAPTCHA_OK")
            {
                if (_captchaDialog != null && !_captchaDialog.IsDisposed)
                {
                    _captchaDialog.DialogResult = DialogResult.OK;
                    _captchaDialog.Close();
                }
                MessageBox.Show("CAPTCHA solved successfully! You can now proceed.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            // כישלון בפתרון ה-CAPTCHA
            else if (response == "CAPTCHA_FAILED")
            {
                MessageBox.Show("Incorrect CAPTCHA code. Please try again with the new image.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            // קוד אימות נשלח במייל (בעת הרשמה או התחברות)
            else if (response == "VERIFY_REGIST_CODE_SENT" || response == "VERIFY_LOGIN_CODE_SENT")
            {
                MessageBox.Show("A verification code has been sent to your email!");
                SwitchToVerification();
            }
            // קוד איפוס סיסמה נשלח למייל
            else if (response == "RESET_CODE_SENT" || response == "VERIFY_RESET_CODE_SENT")
            {
                MessageBox.Show("A password reset code has been sent to your email!", "Code Sent", MessageBoxButtons.OK, MessageBoxIcon.Information);
                SwitchToResetPassword();
            }
            // אימות מוצלח והתחברות למערכת (בדיקת StartsWith לתפיסת ה-Token)
            else if (response.StartsWith("LOGIN OK") || response == "CODE_VERIFIED_SUCCESS")
            {
                MessageBox.Show("Authentication successful!");
                CH.OnMessageReceived -= ProcessServerMessage;
                this.Hide();
            }
            // אישור מהשרת שהסיסמה אופסה בהצלחה
            else if (response == "PASSWORD_RESET_SUCCESS" || response == "PASSWORD_CHANGED")
            {
                MessageBox.Show("Password changed successfully! Please log in with your new password.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

                txbResetCode.Clear();
                txbNewPassword.Clear();

                SwitchToLogin();
            }
            // משתמש חדש נוצר בהצלחה
            else if (response == "User created successfully")
            {
                MessageBox.Show("Registration successful! You can now log in.");
                SwitchToLogin();
            }
            // קוד אימות שגוי
            else if (response == "INVALID_VERIFICATION_CODE" || response == "INVALID_CODE")
            {
                MessageBox.Show("Invalid verification code. Please try again.");
            }
            // השרת מלא
            else if (response == "SERVER FULL")
            {
                MessageBox.Show("Server is full!");
            }
            // הודעות כלליות אחרות מהשרת
            else
            {
                MessageBox.Show("Server Notification: " + response);
            }
        }

        /// <summary>
        /// יוצר ומציג חלון דיאלוג ייעודי להצגת תמונת ה-CAPTCHA (שפוענחה מ-Base64) וקליטת הפתרון מהמשתמש.
        /// </summary>
        /// <param name="base64Image">מחרוזת ה-Base64 המייצגת את תמונת ה-CAPTCHA.</param>
        private void DisplayCaptchaWindow(string base64Image)
        {
            if (_captchaDialog != null && !_captchaDialog.IsDisposed)
            {
                _captchaDialog.Close();
            }

            // פענוח מחרוזת ה-Base64 לאובייקט תמונה
            byte[] imageBytes = Convert.FromBase64String(base64Image);
            Image captchaImg;
            using (MemoryStream ms = new MemoryStream(imageBytes))
            {
                using (Image tempImg = Image.FromStream(ms))
                {
                    captchaImg = new Bitmap(tempImg);
                }
            }

            // יצירת חלון דיאלוג באופן דינמי
            _captchaDialog = new Form
            {
                Width = 260,
                Height = 220,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                Text = "Security Check",
                StartPosition = FormStartPosition.CenterParent,
                MaximizeBox = false,
                MinimizeBox = false
            };

            // רכיב להצגת תמונת ה-CAPTCHA
            PictureBox pb = new PictureBox
            {
                Image = captchaImg,
                Location = new Point(30, 15),
                Size = new Size(180, 60),
                SizeMode = PictureBoxSizeMode.StretchImage
            };

            // תיבת טקסט להזנת הקוד
            TextBox tbInput = new TextBox
            {
                Location = new Point(30, 85),
                Size = new Size(180, 25),
                Font = new Font("Arial", 12)
            };

            // כפתור שליחה
            Button btnSubmit = new Button
            {
                Text = "Submit",
                Location = new Point(65, 125),
                Size = new Size(110, 30)
            };

            // אירוע לחיצה על כפתור השליחה
            btnSubmit.Click += (s, e) =>
            {
                string userCaptcha = tbInput.Text.Trim();
                if (!string.IsNullOrEmpty(userCaptcha))
                {
                    btnSubmit.Enabled = false;
                    CH.SendMessage($"#VerifyCaptcha {userCaptcha}");
                }
            };

            // הוספת הרכיבים לחלון והצגתו
            _captchaDialog.Controls.Add(pb);
            _captchaDialog.Controls.Add(tbInput);
            _captchaDialog.Controls.Add(btnSubmit);

            _captchaDialog.Show(this);
        }

        /// <summary>
        /// מטפל בלחיצה על כפתור ההתחברות ושולח את שם המשתמש והסיסמה לשרת.
        /// </summary>
        private void loginbtn_Click(object sender, EventArgs e)
        {
            string username = txbuserlogin.Text.Trim();
            string password = txbpasslogin.Text.Trim();

            if (string.IsNullOrWhiteSpace(username) || username == "Username")
            {
                MessageBox.Show("Please enter a username");
                return;
            }

            _currentUsername = username;
            CH.SendMessage($"#Login #Username {username} #Password {password}");
        }

        /// <summary>
        /// מטפל בלחיצה על כפתור ההרשמה, אוסף את נתוני המשתמש מהטופס ושולח בקשת הרשמה לשרת.
        /// </summary>
        private void registbtn_Click(object sender, EventArgs e)
        {
            string username = txbusername.Text.Trim();

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(txbpassword.Text))
            {
                MessageBox.Show("Please fill in all required fields");
                return;
            }

            string city = comboBox1.SelectedItem?.ToString() ?? "Unknown";
            _currentUsername = username;

            string message = $"#Regist #Username {username} #password {txbpassword.Text.Trim()} " +
                             $"#fname {txbfname.Text.Trim()} #lname {txblname.Text.Trim()} #email {txbemail.Text.Trim()} #city {city}";

            CH.SendMessage(message);
        }

        /// <summary>
        /// מטפל בלחיצה על כפתור אימות הקוד (OTP) ושולח את הקוד שהזין המשתמש לשרת.
        /// </summary>
        private void conbtn_Click(object sender, EventArgs e)
        {
            string code = txbcode.Text.Trim();

            if (string.IsNullOrWhiteSpace(code) || code == "Code")
            {
                MessageBox.Show("Please enter the verification code.");
                return;
            }

            CH.SendMessage($"#VerifyCode {code} #Username {_currentUsername}");
        }

        /// <summary>
        /// מעביר את תצוגת ממשק המשתמש למסך אימות הקוד (OTP).
        /// </summary>
        public void SwitchToVerification()
        {
            groupBox1.Visible = false;
            groupBox2.Visible = false;
            groupBox4.Visible = false;

            groupBox3.Location = groupBox1.Location;
            groupBox3.Visible = true;
            this.Text = "Verification";
        }

        /// <summary>
        /// מעביר את תצוגת ממשק המשתמש למסך ההתחברות (Login) ומאפס את השאר.
        /// </summary>
        public void SwitchToLogin()
        {
            groupBox1.Visible = false; // Register
            groupBox3.Visible = false; // Verification / OTP
            groupBox4.Visible = false; // Reset Password

            groupBox2.Location = groupBox1.Location;
            groupBox2.Visible = true;  // Login
            this.Text = "Login";
        }

        /// <summary>
        /// מעביר את תצוגת ממשק המשתמש למסך ההרשמה (Register).
        /// </summary>
        private void SwitchToRegister()
        {
            groupBox2.Visible = false;
            groupBox3.Visible = false;
            groupBox4.Visible = false;

            groupBox1.Visible = true;
            this.Text = "Register";
        }

        /// <summary>
        /// מעביר את תצוגת ממשק המשתמש למסך איפוס הסיסמה (groupBox4).
        /// </summary>
        public void SwitchToResetPassword()
        {
            groupBox1.Visible = false;
            groupBox2.Visible = false;
            groupBox3.Visible = false;

            groupBox4.Location = groupBox1.Location;
            groupBox4.Visible = true;
            this.Text = "Reset Password";
        }

        /// <summary>
        /// אירוע טעינת הטופס - מאתחל את מצבי התצוגה ומציב טקסטים מנחים (Placeholders) בתיבות הטקסט.
        /// </summary>
        private void Form1_Load(object sender, EventArgs e)
        {
            groupBox3.Visible = false;

            txbfname.Text = "First Name"; txbfname.ForeColor = Color.Gray;
            txbusername.Text = "Username"; txbusername.ForeColor = Color.Gray;
            txbpassword.Text = "Password"; txbpassword.ForeColor = Color.Gray;
            txblname.Text = "Last Name"; txblname.ForeColor = Color.Gray;
            txbemail.Text = "Email"; txbemail.ForeColor = Color.Gray;
            txbuserlogin.Text = "Username"; txbuserlogin.ForeColor = Color.Gray;
            txbpasslogin.Text = "Password"; txbpasslogin.ForeColor = Color.Gray;
            txbcode.Text = "Code"; txbcode.ForeColor = Color.Gray;
        }

        /// <summary>
        /// מטפל בלחיצה על כפתור "שכחתי סיסמה" - בודק ששם המשתמש הוגדר,
        /// שולח בקשת שחזור לשרת ומעביר את ממשק המשתמש למסך האימות.
        /// </summary>
        private void btnForgotPassword_Click(object sender, EventArgs e)
        {
            string username = txbuserlogin.Text.Trim();
            if (string.IsNullOrEmpty(username) || username == "Username")
            {
                MessageBox.Show("Please enter your username in the login field first.");
                return;
            }

            _currentUsername = username;
            CH.SendMessage($"#ForgotPassword #Username {username}");
        }

        /// <summary>
        /// מטפל בלחיצה על כפתור אישור איפוס הסיסמה - אוסף את שם המשתמש, הקוד שהתקבל במייל
        /// והסיסמה החדשה, ושולח אותם לשרת לצורך עדכון.
        /// </summary>
        private void btnSubmitReset_Click(object sender, EventArgs e)
        {
            string username = txbuserlogin.Text.Trim();
            string code = txbResetCode.Text.Trim();
            string newPassword = txbNewPassword.Text.Trim();

            if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(newPassword))
            {
                MessageBox.Show("Please enter both the verification code and your new password.");
                return;
            }

            CH.SendMessage($"#ResetPassword #Username {username} #Code {code} #NewPassword {newPassword}");
        }

        /// <summary>
        /// מנתק את הלקוח מהשרת בצורה מסודרת בעת סגירת החלון.
        /// </summary>
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            CH.OnMessageReceived -= ProcessServerMessage;
            CH.Disconnect();
        }

        private void Register_Click(object sender, EventArgs e) => SwitchToRegister();

        private void Show_Login_Click(object sender, EventArgs e) => SwitchToLogin();

        private void rtrbtn_Click(object sender, EventArgs e) => SwitchToRegister();
    }
}