using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Windows.Forms;
using System.Xml;

namespace EBS_Rdp_Brute_Force_Detected
{
    public partial class Form1 : Form
    {
        private EventLogWatcher rdpWatcher;

        public Form1()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
        }
        private NotifyIcon notifyIcon;
        private ContextMenuStrip contextMenu;
        private bool autoBlockEnabled = true; 

        private void InitializeNotifyIcon()
        {
            notifyIcon = new NotifyIcon();
            notifyIcon.Icon = SystemIcons.Warning; 
            notifyIcon.Visible = true;
        }
        private void Form1_Load(object sender, EventArgs e)
        {

            InitializeDataGridView();
            LoadPastRdpLogins();
            InitializeNotifyIcon();
            StartRdpWatcher();
            InitializeContextMenu();
        }

        private void InitializeDataGridView()
        {
            dataGridView1.Columns.Add("TimeCreated", "🕒 Zaman");
            dataGridView1.Columns.Add("Username", "👤 Kullanıcı");
            dataGridView1.Columns.Add("IpAddress", "🌐 IP Adresi");
            dataGridView1.Columns.Add("LogonType", "🔐 Logon Türü");
            dataGridView1.Columns.Add("Workstation", "🖥️ İstemci Adı");
            dataGridView1.Columns.Add("FailureReason", "❌ Hata Nedeni");
            dataGridView1.Columns.Add("ProcessName", "⚙️ Uygulama");
            dataGridView1.Columns.Add("AuthPackage", "🔐 Doğrulama Paketi");
            dataGridView1.Columns.Add("GeoInfo", "📍 Lokasyon");

        }

        private void LoadPastRdpLogins()
        {
            var attempts = GetPastRdpLogins();
            foreach (var attempt in attempts)
            {
                if (attempt.LogonType == "10")
                {
                    dataGridView1.Rows.Add(
                        attempt.TimeCreated,
                        attempt.Username,
                        attempt.IpAddress,
                        attempt.LogonType,
                        attempt.Workstation,
                        TranslateFailureReason(attempt.FailureReason),
                        attempt.ProcessName,
                        attempt.AuthPackage,
                        GetGeoInfo(attempt.IpAddress)
                    );

                }
            }
        }

        private void StartRdpWatcher()
        {
            string query = "*[System/EventID=4625]";
            EventLogQuery eventQuery = new EventLogQuery("Security", PathType.LogName, query);
            rdpWatcher = new EventLogWatcher(eventQuery);
            rdpWatcher.EventRecordWritten += RdpWatcher_EventRecordWritten;
            rdpWatcher.Enabled = true;
        }

        private void RdpWatcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                RdpLoginAttempt attempt = ParseEventRecord(e.EventRecord);

                if (attempt.LogonType == "3")
                {
                    this.Invoke((MethodInvoker)delegate
                    {
                        dataGridView1.Rows.Add(
                            attempt.TimeCreated,
                            attempt.Username,
                            attempt.IpAddress,
                            attempt.LogonType,
                            attempt.Workstation,
                            TranslateFailureReason(attempt.FailureReason),
                            attempt.ProcessName,
                            attempt.AuthPackage,
                            GetGeoInfo(attempt.IpAddress)
                        );

                        // Bildirim göster
                        notifyIcon.ShowBalloonTip(
                            5000, // 5 saniye görünür
                            "RDP Brute Force Tespit Edildi!",
                            $"Kullanıcı: {attempt.Username}\nIP: {attempt.IpAddress}\nHata: {TranslateFailureReason(attempt.FailureReason)}",
                            ToolTipIcon.Warning
                        );

                        // Sesli uyarı
                        System.Media.SystemSounds.Exclamation.Play();
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hata: " + ex.Message);
            }
        }

        private List<RdpLoginAttempt> GetPastRdpLogins()
        {
            var attempts = new List<RdpLoginAttempt>();
            string query = "*[System/EventID=4625]";
            EventLogQuery eventQuery = new EventLogQuery("Security", PathType.LogName, query);

            using (EventLogReader reader = new EventLogReader(eventQuery))
            {
                for (EventRecord record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
                {
                    try
                    {
                        RdpLoginAttempt attempt = ParseEventRecord(record);
                        if (attempt.LogonType == "3")
                        {
                            attempts.Add(attempt);
                        }
                    }
                    catch { continue; }
                }
            }

            return attempts;
        }

        private RdpLoginAttempt ParseEventRecord(EventRecord record)
        {
            string xml = record.ToXml();
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);

            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("ev", "http://schemas.microsoft.com/win/2004/08/events/event");

            return new RdpLoginAttempt
            {
                TimeCreated = record.TimeCreated,
                Username = doc.SelectSingleNode("//ev:Data[@Name='TargetUserName']", ns)?.InnerText,
                IpAddress = doc.SelectSingleNode("//ev:Data[@Name='IpAddress']", ns)?.InnerText,
                LogonType = doc.SelectSingleNode("//ev:Data[@Name='LogonType']", ns)?.InnerText,
                Workstation = doc.SelectSingleNode("//ev:Data[@Name='WorkstationName']", ns)?.InnerText,
                ProcessName = doc.SelectSingleNode("//ev:Data[@Name='ProcessName']", ns)?.InnerText,
                FailureReason = doc.SelectSingleNode("//ev:Data[@Name='FailureReason']", ns)?.InnerText,
                AuthPackage = doc.SelectSingleNode("//ev:Data[@Name='AuthenticationPackageName']", ns)?.InnerText
            };
        }

        private string TranslateFailureReason(string code)
        {
            switch (code)
            {
                case "%%2313": return "Kullanıcı adı ya da şifre hatalı";
                case "%%2310": return "Kullanıcıya izin verilmedi";
                case "%%2312": return "Giriş yöntemi engellendi";
                default: return code;
            }
        }
        private void InitializeContextMenu()
        {
            contextMenu = new ContextMenuStrip();

            var blockIpItem = new ToolStripMenuItem("IP'yi Engelle");
            blockIpItem.Click += BlockIpItem_Click;
            contextMenu.Items.Add(blockIpItem);

            var unblockIpItem = new ToolStripMenuItem("IP Engellemesini Kaldır");
            unblockIpItem.Click += UnblockIpItem_Click;
            contextMenu.Items.Add(unblockIpItem);

            dataGridView1.ContextMenuStrip = contextMenu;
            dataGridView1.MouseDown += DataGridView1_MouseDown;
        }
        private void UnblockIpItem_Click(object sender, EventArgs e)
        {
            if (dataGridView1.CurrentCell == null) return;

            int ipColIndex = dataGridView1.Columns["IpAddress"].Index;
            int rowIndex = dataGridView1.CurrentCell.RowIndex;

            var ipCell = dataGridView1.Rows[rowIndex].Cells[ipColIndex];
            string ip = ipCell.Value?.ToString();

            if (string.IsNullOrWhiteSpace(ip))
            {
                MessageBox.Show("IP adresi boş veya geçersiz.", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            DialogResult dr = MessageBox.Show($"{ip} IP adresinin engellemesini kaldırmak istediğinize emin misiniz?",
                "IP Engellemesini Kaldır", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

            if (dr == DialogResult.Yes)
            {
                bool success = UnblockIp(ip);
                if (success)
                {
                    MessageBox.Show($"IP {ip} için engelleme kaldırıldı.", "Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show($"IP {ip} engelleme kaldırılırken hata oluştu.", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        private bool UnblockIp(string ip)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall delete rule name=\"BlockIP_{ip}\"",
                    Verb = "runas", 
                    CreateNoWindow = true,
                    UseShellExecute = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                };

                var process = System.Diagnostics.Process.Start(psi);
                process.WaitForExit();

                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Firewall engelleme kaldırma hatası: " + ex.Message);
                return false;
            }
        }
        
        private void DataGridView1_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                var hit = dataGridView1.HitTest(e.X, e.Y);
                if (hit.RowIndex >= 0 && hit.ColumnIndex >= 0)
                {
                    dataGridView1.ClearSelection();
                    dataGridView1.Rows[hit.RowIndex].Cells[hit.ColumnIndex].Selected = true;
                    dataGridView1.CurrentCell = dataGridView1.Rows[hit.RowIndex].Cells[hit.ColumnIndex];
                }
                else
                {
                    contextMenu.Hide();
                }
            }
        }

        private void BlockIpItem_Click(object sender, EventArgs e)
        {
            if (dataGridView1.CurrentCell == null) return;

            int ipColIndex = dataGridView1.Columns["IpAddress"].Index;
            int rowIndex = dataGridView1.CurrentCell.RowIndex;

            var ipCell = dataGridView1.Rows[rowIndex].Cells[ipColIndex];
            string ip = ipCell.Value?.ToString();

            if (string.IsNullOrWhiteSpace(ip))
            {
                MessageBox.Show("IP adresi boş veya geçersiz.", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            DialogResult dr = MessageBox.Show($"{ip} IP adresini güvenlik duvarına engellemek istediğinize emin misiniz?",
                "IP Engelle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (dr == DialogResult.Yes)
            {
                bool success = BlockIp(ip);
                if (success)
                {
                    MessageBox.Show($"IP {ip} başarıyla engellendi.", "Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show($"IP {ip} engellenirken hata oluştu.", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private bool BlockIp(string ip)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall add rule name=\"BlockIP_{ip}\" dir=in interface=any action=block remoteip={ip}",
                    Verb = "runas",
                    CreateNoWindow = true,
                    UseShellExecute = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                };

                var process = System.Diagnostics.Process.Start(psi);
                process.WaitForExit();

                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Firewall engelleme hatası: " + ex.Message);
                return false;
            }
        }
        private string GetGeoInfo(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return "Bilinmiyor";

            if (ip.StartsWith("192.") || ip.StartsWith("10.") || ip.StartsWith("172.") || ip.StartsWith("127.") || ip == "::1")
            {
                return "Local IP";
            }

            try
            {
                using (var client = new System.Net.WebClient())
                {
                    string json = client.DownloadString($"http://ip-api.com/json/{ip}?fields=status,country,city,org,query");
                    dynamic obj = Newtonsoft.Json.JsonConvert.DeserializeObject(json);

                    if (obj.status == "success")
                    {
                        return $"{obj.country}, {obj.city} ({obj.org})";
                    }
                    else
                    {
                        return "Sorgu Başarısız";
                    }
                }
            }
            catch
            {
                return "Sorgulama Hatası";
            }
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            autoBlockEnabled = checkBox1.Checked;

            if (autoBlockEnabled)
            {
                checkBox1.Text = "✅ Otomatik Engelle (Açık)";
            }
            else
            {
                checkBox1.Text = "⛔ Otomatik Engelle (Kapalı)";
            }
        }

    }

    public class RdpLoginAttempt
    {
        public DateTime? TimeCreated { get; set; }
        public string Username { get; set; }
        public string IpAddress { get; set; }
        public string LogonType { get; set; }
        public string Workstation { get; set; }
        public string ProcessName { get; set; }
        public string FailureReason { get; set; }
        public string AuthPackage { get; set; }
    }
}