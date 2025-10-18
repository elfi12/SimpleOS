using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Net;
using System.Threading;

namespace SimpleOS
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Kernel os = new Kernel();
            os.Start();
        }
    }

    public enum UserType
    {
        User,
        Operator,
        Developer
    }

    public class User
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string HomeDirectory { get; set; } = "";
        public UserType UserType { get; set; } = UserType.User;
    }

    public class ConsoleDriver
    {
        public void Clear() => Console.Clear();
        public void Write(string text) => Console.Write(text);
        public void WriteLine(string text = "") => Console.WriteLine(text);
        public string ReadLine() => Console.ReadLine() ?? "";
    }

    public class FileSystem
    {
        private string systemRoot;
        public FileSystem(string rootPath)
        {
            systemRoot = rootPath;
            InitializeFileSystem();
        }

        private void InitializeFileSystem()
        {
            CreateRealDirectory("/");
            CreateRealDirectory("/home");
            CreateRealDirectory("/home/user");
            CreateRealDirectory("/home/operator");
            CreateRealDirectory("/home/dev");
            CreateRealDirectory("/root");
            CreateRealDirectory("/etc");
            CreateRealDirectory("/var");
            CreateRealDirectory("/var/log");
            CreateRealDirectory("/var/lib");
            CreateRealDirectory("/var/lib/packages");
            CreateRealDirectory("/tmp");
            CreateRealDirectory("/usr");
            CreateRealDirectory("/bin");
            CreateRealDirectory("/usr/local/bin");

            CreateRealFile("/etc/motd", "Welcome to SimpleOS v3.7 'Stable Release'!\nNew features: Network, Packages, Background Jobs\n");
            CreateRealFile("/etc/version", "SimpleOS 3.7.0 Stable Release\n");
            CreateRealFile("/var/log/system.log", GenerateSystemLog());
            CreateRealFile("/home/user/readme.txt", "Welcome! New in v3.7: Network commands, Package management, Background jobs\n");

            // Создаем несколько тестовых файлов для демонстрации
            CreateRealFile("/home/user/document.txt", "This is a test document.\nLine 2 of the document.\nAnother line for testing grep.");
            CreateRealFile("/home/user/data.csv", "name,age,city\nJohn,25,New York\nAlice,30,London\nBob,22,Tokyo");
        }

        private string GenerateSystemLog()
        {
            return $"SimpleOS System Log - v3.7\nBoot Time: {DateTime.Now}\nSystem Root: {systemRoot}\n";
        }

        public string GetRealPath(string virtualPath)
        {
            if (virtualPath == "/") return systemRoot;
            string relativePath = virtualPath.TrimStart('/');
            return Path.Combine(systemRoot, relativePath);
        }

        public string GetVirtualPath(string realPath)
        {
            if (realPath == systemRoot) return "/";
            if (realPath.StartsWith(systemRoot))
                return "/" + realPath.Substring(systemRoot.Length).TrimStart(Path.DirectorySeparatorChar);
            return realPath;
        }

        private void CreateRealDirectory(string virtualPath)
        {
            string realPath = GetRealPath(virtualPath);
            if (!Directory.Exists(realPath))
                Directory.CreateDirectory(realPath);
        }

        private void CreateRealFile(string virtualPath, string content)
        {
            string realPath = GetRealPath(virtualPath);
            string directory = Path.GetDirectoryName(realPath);
            if (!Directory.Exists(directory))
                Directory.CreateDirectory(directory);
            if (!File.Exists(realPath))
                File.WriteAllText(realPath, content);
        }
    }

    public class TranslationManager
    {
        private Dictionary<string, Dictionary<string, string>> translations;
        private Dictionary<string, string> languageNames;

        public TranslationManager()
        {
            InitializeTranslations();
        }

        private void InitializeTranslations()
        {
            translations = new Dictionary<string, Dictionary<string, string>>();
            languageNames = new Dictionary<string, string>();

            translations["en"] = new Dictionary<string, string>
            {
                ["welcome_message"] = "Welcome to SimpleOS v3.7!",
                ["type_help"] = "Type 'help' for commands",
                ["available_commands"] = "Available Commands",
                ["command_not_found"] = "Command not found: {0}",
                ["login_successful"] = "Login successful! Welcome, {0}",
                ["login_failed"] = "Login failed!",
                ["logout_message"] = "Goodbye, {0}!",
                ["permission_denied"] = "Permission denied",
                ["file_not_found"] = "File not found: {0}",
                ["directory_not_found"] = "Directory not found: {0}"
            };
            languageNames["en"] = "English";

            translations["ru"] = new Dictionary<string, string>
            {
                ["welcome_message"] = "Добро пожаловать в SimpleOS v3.7!",
                ["type_help"] = "Введите 'help' для списка команд",
                ["available_commands"] = "Доступные команды",
                ["command_not_found"] = "Команда не найдена: {0}",
                ["login_successful"] = "Вход выполнен! Добро пожаловать, {0}",
                ["login_failed"] = "Ошибка входа!",
                ["logout_message"] = "До свидания, {0}!",
                ["permission_denied"] = "Доступ запрещен",
                ["file_not_found"] = "Файл не найден: {0}",
                ["directory_not_found"] = "Директория не найдена: {0}"
            };
            languageNames["ru"] = "Русский";
        }

        public string Translate(string key, string language, params object[] args)
        {
            if (!translations.ContainsKey(language) || !translations[language].ContainsKey(key))
            {
                if (translations["en"].ContainsKey(key))
                    return string.Format(translations["en"][key], args);
                return key;
            }
            return string.Format(translations[language][key], args);
        }

        public bool IsLanguageSupported(string language) => translations.ContainsKey(language);
        public string GetLanguageName(string language) => languageNames.ContainsKey(language) ? languageNames[language] : language;
    }

    public class UserManager
    {
        private List<User> users;
        public string UsersFilePath { get; private set; }
        private string systemRoot;
        private Dictionary<string, string> userLanguages;

        public UserManager(string rootPath)
        {
            systemRoot = rootPath;
            UsersFilePath = Path.Combine(systemRoot, "etc", "users.json");
            userLanguages = new Dictionary<string, string>();
            users = new List<User>();
            LoadUsers();
        }

        private void LoadUsers()
        {
            try
            {
                if (File.Exists(UsersFilePath))
                {
                    string json = File.ReadAllText(UsersFilePath);
                    var loadedUsers = JsonSerializer.Deserialize<List<User>>(json);
                    if (loadedUsers != null && loadedUsers.Count > 0)
                    {
                        users = loadedUsers;
                        return;
                    }
                }
                InitializeDefaultUsers();
                SaveUsers();
            }
            catch
            {
                InitializeDefaultUsers();
            }
        }

        public void SaveUsers()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(UsersFilePath));
                string json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(UsersFilePath, json);
            }
            catch { }
        }

        private void InitializeDefaultUsers()
        {
            users.Add(new User { Username = "user", Password = "password", HomeDirectory = "/home/user", UserType = UserType.User });
            users.Add(new User { Username = "operator", Password = "op123", HomeDirectory = "/home/operator", UserType = UserType.Operator });
            users.Add(new User { Username = "dev", Password = "dev123", HomeDirectory = "/home/dev", UserType = UserType.Developer });
            users.Add(new User { Username = "root", Password = "toor", HomeDirectory = "/root", UserType = UserType.Developer });
        }

        public User Authenticate(string username, string password) => users.FirstOrDefault(u => u.Username == username && u.Password == password);
        public bool AddUser(string username, string password, UserType userType = UserType.User)
        {
            if (users.Any(u => u.Username == username)) return false;
            users.Add(new User { Username = username, Password = password, HomeDirectory = $"/home/{username}", UserType = userType });
            return true;
        }
        public bool ChangePassword(string username, string newPassword)
        {
            var user = users.FirstOrDefault(u => u.Username == username);
            if (user != null) { user.Password = newPassword; return true; }
            return false;
        }
        public void SetUserLanguage(string username, string language) => userLanguages[username] = language;
        public string GetUserLanguage(string username) => userLanguages.ContainsKey(username) ? userLanguages[username] : null;
        public List<User> GetAllUsers() => new List<User>(users);
        public int GetUserCount() => users.Count;
    }

    public class Application
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Command { get; set; } = "";
    }

    public class ApplicationManager
    {
        private Dictionary<string, Application> applications;
        public ApplicationManager() => InitializeApplications();

        private void InitializeApplications()
        {
            applications = new Dictionary<string, Application>
            {
                ["browser"] = new Application { Name = "browser", Description = "Simple web browser", Command = "run_browser" },
                ["textedit"] = new Application { Name = "textedit", Description = "Text editor with syntax highlighting", Command = "run_textedit" },
                ["calculator"] = new Application { Name = "calculator", Description = "Scientific calculator", Command = "run_calculator" },
                ["filemanager"] = new Application { Name = "filemanager", Description = "Graphical file manager", Command = "run_filemanager" },
                ["paint"] = new Application { Name = "paint", Description = "Drawing application", Command = "run_paint" }
            };
        }

        public bool IsApplication(string command) => applications.ContainsKey(command.ToLower());

        public void RunApplication(string appName, string[] args)
        {
            if (applications.TryGetValue(appName.ToLower(), out Application app))
            {
                Console.WriteLine($"🚀 Starting {app.Name}...");

                switch (app.Command)
                {
                    case "run_browser":
                        RunBrowser(args);
                        break;
                    case "run_textedit":
                        RunTextEdit(args);
                        break;
                    case "run_calculator":
                        RunCalculator(args);
                        break;
                    case "run_filemanager":
                        RunFileManager(args);
                        break;
                    case "run_paint":
                        RunPaint(args);
                        break;
                }
            }
            else
            {
                Console.WriteLine($"Application '{appName}' not found");
            }
        }

        private void RunBrowser(string[] args)
        {
            string url = args.Length > 0 ? args[0] : "https://example.com";
            Console.WriteLine($"🌐 Opening browser: {url}");
            Console.WriteLine("🖥️ Rendering web page...");
            Console.WriteLine("┌─────────────────────────────────────┐");
            Console.WriteLine("│          Example Website            │");
            Console.WriteLine("├─────────────────────────────────────┤");
            Console.WriteLine("│ Welcome to SimpleOS Browser!        │");
            Console.WriteLine("│                                     │");
            Console.WriteLine("│ • Fast and secure browsing          │");
            Console.WriteLine("│ • Tabbed navigation                 │");
            Console.WriteLine("│ • Bookmarks support                 │");
            Console.WriteLine("└─────────────────────────────────────┘");
            Console.WriteLine("Press any key to close browser...");
            Console.ReadKey();
        }

        private void RunTextEdit(string[] args)
        {
            string filename = args.Length > 0 ? args[0] : "newfile.txt";
            Console.WriteLine($"📝 Text Editor - Editing: {filename}");
            Console.WriteLine("┌─────────────────────────────────────┐");
            Console.WriteLine("│ File Edit View Help                 │");
            Console.WriteLine("├─────────────────────────────────────┤");
            Console.WriteLine("│ Lorem ipsum dolor sit amet,         │");
            Console.WriteLine("│ consectetur adipiscing elit.        │");
            Console.WriteLine("│                                     │");
            Console.WriteLine("│ Features:                           │");
            Console.WriteLine("│ • Syntax highlighting               │");
            Console.WriteLine("│ • Multiple tabs                     │");
            Console.WriteLine("│ • Find and replace                  │");
            Console.WriteLine("└─────────────────────────────────────┘");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private void RunCalculator(string[] args)
        {
            Console.WriteLine("🧮 Scientific Calculator");
            Console.WriteLine("┌─────────────────────────────────────┐");
            Console.WriteLine("│ 7   8   9   +   sin  cos            │");
            Console.WriteLine("│ 4   5   6   -   tan  log            │");
            Console.WriteLine("│ 1   2   3   *   √    x²             │");
            Console.WriteLine("│ 0   .   =   /   π    e              │");
            Console.WriteLine("├─────────────────────────────────────┤");
            Console.WriteLine("│ Display: 0                          │");
            Console.WriteLine("└─────────────────────────────────────┘");
            Console.WriteLine("Press any key to close calculator...");
            Console.ReadKey();
        }

        private void RunFileManager(string[] args)
        {
            Console.WriteLine("📁 File Manager");
            Console.WriteLine("┌─────────────────────────────────────┐");
            Console.WriteLine("│ 📁 Documents      📁 Images        │");
            Console.WriteLine("│ 📁 Music          📁 Videos        │");
            Console.WriteLine("│ 📄 readme.txt     📄 notes.md      │");
            Console.WriteLine("│ 📄 config.json    📄 data.csv      │");
            Console.WriteLine("│                                     │");
            Console.WriteLine("│ Free space: 15.2 GB / 128 GB        │");
            Console.WriteLine("└─────────────────────────────────────┘");
            Console.WriteLine("Press any key to close file manager...");
            Console.ReadKey();
        }

        private void RunPaint(string[] args)
        {
            Console.WriteLine("🎨 Paint Application");
            Console.WriteLine("┌─────────────────────────────────────┐");
            Console.WriteLine("│ 🖌️  🎨  🖊️   🧽   📏  🔍          │");
            Console.WriteLine("│                                     │");
            Console.WriteLine("│      ████████████████              │");
            Console.WriteLine("│    ██░░░░░░░░░░░░░░░░██            │");
            Console.WriteLine("│  ██░░░░░░░░░░░░░░░░░░░░██          │");
            Console.WriteLine("│  ██░░░░░░██░░░░██░░░░░░██          │");
            Console.WriteLine("│  ██░░░░░░░░░░░░░░░░░░░░██          │");
            Console.WriteLine("│    ██░░░░██████░░░░░░██            │");
            Console.WriteLine("│      ██████░░░░██████              │");
            Console.WriteLine("└─────────────────────────────────────┘");
            Console.WriteLine("Press any key to close paint...");
            Console.ReadKey();
        }

        public List<Application> GetAvailableApplications() => applications.Values.ToList();
    }

    public class CacheStatistics
    {
        public int TotalFiles { get; set; }
        public long TotalSize { get; set; }
        public int Hits { get; set; }
        public int Misses { get; set; }
        public double HitRatio => TotalAccesses > 0 ? (double)Hits / TotalAccesses : 0;
        public int TotalAccesses => Hits + Misses;
    }

    public class CachedFile
    {
        public string FilePath { get; set; } = "";
        public string Content { get; set; } = "";
        public string Hash { get; set; } = "";
        public int Version { get; set; }
        public DateTime LastAccessed { get; set; }
        public int AccessCount { get; set; }
    }

    public class CacheManager
    {
        private Dictionary<string, CachedFile> fileCache;
        private CacheStatistics statistics;

        public CacheManager()
        {
            fileCache = new Dictionary<string, CachedFile>();
            statistics = new CacheStatistics();
        }

        public void InitializeUserCache(string username)
        {
            Console.WriteLine($"📦 Initialized cache for user: {username}");
        }

        public string ComputeFileHash(string filePath, string content)
        {
            using var md5 = MD5.Create();
            byte[] inputBytes = Encoding.UTF8.GetBytes(content);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hashBytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public void CacheFile(string filePath, string content)
        {
            var cachedFile = new CachedFile
            {
                FilePath = filePath,
                Content = content,
                Hash = ComputeFileHash(filePath, content),
                Version = 1,
                LastAccessed = DateTime.Now,
                AccessCount = 1
            };

            fileCache[filePath] = cachedFile;
            statistics.TotalFiles++;
            statistics.TotalSize += content.Length;
            statistics.Hits++;
        }

        public CachedFile GetCachedFile(string filePath)
        {
            if (fileCache.TryGetValue(filePath, out CachedFile cachedFile))
            {
                cachedFile.LastAccessed = DateTime.Now;
                cachedFile.AccessCount++;
                statistics.Hits++;
                return cachedFile;
            }
            statistics.Misses++;
            return null;
        }

        public void ClearCache()
        {
            int fileCount = fileCache.Count;
            long totalSize = statistics.TotalSize;

            fileCache.Clear();
            statistics = new CacheStatistics();

            Console.WriteLine($"🗑️  Cache cleared: {fileCount} files, {totalSize} bytes freed");
        }

        public List<CachedFile> GetCachedFiles() => fileCache.Values.ToList();

        public CacheStatistics GetCacheStatistics() => statistics;
    }

    public class NetworkManager
    {
        public string Status => "Operational";

        public List<NetworkInterface> GetNetworkInterfaces()
        {
            return new List<NetworkInterface>
            {
                new NetworkInterface { Name = "lo0", IP = "127.0.0.1", Status = "UP" },
                new NetworkInterface { Name = "eth0", IP = "192.168.1.100", Status = "UP" },
                new NetworkInterface { Name = "wlan0", IP = "192.168.1.101", Status = "UP" }
            };
        }

        public List<NetworkConnection> GetActiveConnections()
        {
            return new List<NetworkConnection>
            {
                new NetworkConnection { Protocol = "TCP", Local = "127.0.0.1:22", Remote = "0.0.0.0:0", State = "LISTEN" },
                new NetworkConnection { Protocol = "TCP", Local = "192.168.1.100:443", Remote = "93.184.216.34:12345", State = "ESTABLISHED" }
            };
        }
    }

    public class NetworkInterface
    {
        public string Name { get; set; } = "";
        public string IP { get; set; } = "";
        public string Status { get; set; } = "DOWN";
    }

    public class NetworkConnection
    {
        public string Protocol { get; set; } = "";
        public string Local { get; set; } = "";
        public string Remote { get; set; } = "";
        public string State { get; set; } = "";
    }

    public class Package
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime InstallDate { get; set; }
        public long Size { get; set; }
    }

    public class PackageManager
    {
        private string packagesPath;
        private List<Package> installedPackages;
        private Dictionary<string, Package> availablePackages;

        public PackageManager(string systemRoot)
        {
            packagesPath = Path.Combine(systemRoot, "var", "lib", "packages");
            installedPackages = new List<Package>();
            InitializeAvailablePackages();
            LoadPackages();
        }

        private void InitializeAvailablePackages()
        {
            availablePackages = new Dictionary<string, Package>
            {
                ["git"] = new Package { Name = "git", Version = "2.34.1", Description = "Distributed version control system", Size = 20480 },
                ["python"] = new Package { Name = "python", Version = "3.9.7", Description = "Python programming language", Size = 40960 },
                ["nodejs"] = new Package { Name = "nodejs", Version = "16.13.0", Description = "JavaScript runtime", Size = 30720 },
                ["nginx"] = new Package { Name = "nginx", Version = "1.21.3", Description = "Web server", Size = 15360 },
                ["mysql"] = new Package { Name = "mysql", Version = "8.0.27", Description = "Database server", Size = 81920 }
            };
        }

        public bool InstallPackage(string name)
        {
            if (availablePackages.TryGetValue(name, out Package package))
            {
                if (!installedPackages.Any(p => p.Name == name))
                {
                    var installedPackage = new Package
                    {
                        Name = package.Name,
                        Version = package.Version,
                        Description = package.Description,
                        InstallDate = DateTime.Now,
                        Size = package.Size
                    };

                    installedPackages.Add(installedPackage);
                    SavePackages();

                    Console.WriteLine($"📦 Installing {name} ({package.Version})...");
                    SimulateInstallationProgress();
                    Console.WriteLine($"✅ {name} installed successfully ({package.Size} bytes)");
                    return true;
                }
                else
                {
                    Console.WriteLine($"ℹ️  Package {name} is already installed");
                    return true;
                }
            }
            else
            {
                Console.WriteLine($"❌ Package {name} not found in repository");
                return false;
            }
        }

        public bool RemovePackage(string name)
        {
            var package = installedPackages.FirstOrDefault(p => p.Name == name);
            if (package != null)
            {
                installedPackages.Remove(package);
                SavePackages();
                Console.WriteLine($"🗑️  Removing {name}...");
                Thread.Sleep(1000);
                Console.WriteLine($"✅ {name} removed successfully");
                return true;
            }
            Console.WriteLine($"❌ Package {name} is not installed");
            return false;
        }

        public List<Package> GetInstalledPackages() => installedPackages;

        public List<Package> GetAvailablePackages() => availablePackages.Values.ToList();

        public void SearchPackages(string query)
        {
            var results = availablePackages.Values
                .Where(p => p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                           p.Description.Contains(query, StringComparison.OrdinalIgnoreCase))
                .ToList();

            Console.WriteLine($"🔍 Search results for '{query}':");
            foreach (var pkg in results)
            {
                Console.WriteLine($"  {pkg.Name} ({pkg.Version}) - {pkg.Description}");
            }
        }

        private void SimulateInstallationProgress()
        {
            for (int i = 0; i <= 100; i += 10)
            {
                Console.Write($"\rProgress: [{new string('█', i / 10)}{new string('░', 10 - i / 10)}] {i}%");
                Thread.Sleep(200);
            }
            Console.WriteLine();
        }

        private void LoadPackages()
        {
            try
            {
                string filePath = Path.Combine(packagesPath, "installed.json");
                if (File.Exists(filePath))
                {
                    string json = File.ReadAllText(filePath);
                    installedPackages = JsonSerializer.Deserialize<List<Package>>(json) ?? new List<Package>();
                }
            }
            catch
            {
                installedPackages = new List<Package>();
            }
        }

        private void SavePackages()
        {
            try
            {
                Directory.CreateDirectory(packagesPath);
                string filePath = Path.Combine(packagesPath, "installed.json");
                string json = JsonSerializer.Serialize(installedPackages, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(filePath, json);
            }
            catch
            {
                Console.WriteLine("⚠️  Warning: Could not save package database");
            }
        }
    }

    public class BackgroundJob
    {
        public int Id { get; set; }
        public string Command { get; set; } = "";
        public DateTime StartTime { get; set; }
        public string Status { get; set; } = "Running";
        public Thread Thread { get; set; }
        public int Progress { get; set; }
    }

    public class BackgroundJobManager
    {
        private List<BackgroundJob> jobs;
        private int nextJobId = 1;

        public BackgroundJobManager() => jobs = new List<BackgroundJob>();

        public BackgroundJob StartJob(string command)
        {
            var job = new BackgroundJob
            {
                Id = nextJobId++,
                Command = command,
                StartTime = DateTime.Now,
                Status = "Running",
                Progress = 0
            };

            // Запускаем задачу в отдельном потоке
            job.Thread = new Thread(() => ExecuteBackgroundJob(job));
            job.Thread.Start();

            jobs.Add(job);
            return job;
        }

        private void ExecuteBackgroundJob(BackgroundJob job)
        {
            try
            {
                // Симуляция длительной задачи
                for (int i = 0; i <= 100; i += 10)
                {
                    if (job.Status == "Terminated") break;

                    job.Progress = i;
                    Thread.Sleep(1000); // Имитация работы
                }

                job.Status = job.Status == "Terminated" ? "Terminated" : "Completed";
            }
            catch
            {
                job.Status = "Failed";
            }
        }

        public bool KillJob(int jobId)
        {
            var job = jobs.FirstOrDefault(j => j.Id == jobId);
            if (job != null && job.Status == "Running")
            {
                job.Status = "Terminated";
                return true;
            }
            return false;
        }

        public BackgroundJob GetJob(int jobId) => jobs.FirstOrDefault(j => j.Id == jobId);
        public List<BackgroundJob> GetJobs() => jobs;
        public void RemoveJob(int jobId) => jobs.RemoveAll(j => j.Id == jobId);
    }

    public class SimpleCrypto
    {
        public void EncryptFile(string filePath, string password)
        {
            try
            {
                var content = File.ReadAllBytes(filePath);
                var key = DeriveKey(password, 32);
                var iv = GenerateRandomBytes(16);

                // Простое XOR шифрование (для демонстрации)
                for (int i = 0; i < content.Length; i++)
                {
                    content[i] ^= key[i % key.Length];
                }

                // Сохраняем файл с IV в начале
                var result = new byte[iv.Length + content.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(content, 0, result, iv.Length, content.Length);

                File.WriteAllBytes(filePath + ".enc", result);
                Console.WriteLine($"🔐 File encrypted: {filePath}.enc");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Encryption failed: {ex.Message}");
            }
        }

        public bool DecryptFile(string filePath, string password)
        {
            try
            {
                if (!filePath.EndsWith(".enc"))
                {
                    Console.WriteLine("❌ File must have .enc extension");
                    return false;
                }

                var encryptedData = File.ReadAllBytes(filePath);
                if (encryptedData.Length < 16)
                {
                    Console.WriteLine("❌ Invalid encrypted file");
                    return false;
                }

                var iv = new byte[16];
                var content = new byte[encryptedData.Length - 16];
                Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
                Buffer.BlockCopy(encryptedData, 16, content, 0, content.Length);

                var key = DeriveKey(password, 32);

                // Дешифрование
                for (int i = 0; i < content.Length; i++)
                {
                    content[i] ^= key[i % key.Length];
                }

                string outputPath = filePath.Replace(".enc", ".dec");
                File.WriteAllBytes(outputPath, content);
                Console.WriteLine($"🔓 File decrypted: {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Decryption failed: {ex.Message}");
                return false;
            }
        }

        private byte[] DeriveKey(string password, int length)
        {
            using var sha256 = SHA256.Create();
            var key = new byte[length];
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            for (int i = 0; i < length; i++)
            {
                var input = new byte[passwordBytes.Length + 1];
                Buffer.BlockCopy(passwordBytes, 0, input, 0, passwordBytes.Length);
                input[passwordBytes.Length] = (byte)i;
                var hash = sha256.ComputeHash(input);
                key[i] = hash[0];
            }

            return key;
        }

        private byte[] GenerateRandomBytes(int length)
        {
            var bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }
    }

    public class SystemMonitor
    {
        public SystemInfo GetSystemInfo()
        {
            var process = Process.GetCurrentProcess();
            var drive = new DriveInfo(Path.GetPathRoot(Environment.CurrentDirectory));

            return new SystemInfo
            {
                MemoryUsage = process.WorkingSet64,
                TotalMemory = 1024 * 1024 * 1024, // 1GB для демонстрации
                CpuUsage = process.TotalProcessorTime,
                ThreadCount = process.Threads.Count,
                DiskTotal = drive.TotalSize,
                DiskFree = drive.AvailableFreeSpace,
                Uptime = DateTime.Now - process.StartTime
            };
        }

        public List<ProcessInfo> GetRunningProcesses()
        {
            return new List<ProcessInfo>
            {
                new ProcessInfo { PID = 1, Name = "kernel", CPU = 0.5, Memory = 10240, Status = "Running" },
                new ProcessInfo { PID = 2, Name = "filesystem", CPU = 0.2, Memory = 8192, Status = "Running" },
                new ProcessInfo { PID = 3, Name = "network", CPU = 0.1, Memory = 4096, Status = "Running" },
                new ProcessInfo { PID = 4, Name = "user-interface", CPU = 1.2, Memory = 16384, Status = "Running" }
            };
        }
    }

    public class SystemInfo
    {
        public long MemoryUsage { get; set; }
        public long TotalMemory { get; set; }
        public TimeSpan CpuUsage { get; set; }
        public int ThreadCount { get; set; }
        public long DiskTotal { get; set; }
        public long DiskFree { get; set; }
        public TimeSpan Uptime { get; set; }
    }

    public class ProcessInfo
    {
        public int PID { get; set; }
        public string Name { get; set; } = "";
        public double CPU { get; set; }
        public long Memory { get; set; }
        public string Status { get; set; } = "";
    }

    public class Kernel
    {
        private ConsoleDriver console;
        private FileSystem fileSystem;
        private TranslationManager translation;
        private UserManager userManager;
        private ApplicationManager appManager;
        private CacheManager cacheManager;
        private NetworkManager networkManager;
        private PackageManager packageManager;
        private BackgroundJobManager jobManager;
        private SystemMonitor systemMonitor;
        private SimpleCrypto crypto;
        private string currentLanguage = "en";
        private User currentUser;
        private string currentDirectory = "/";
        private List<string> commandHistory = new List<string>();
        private string systemRoot;
        private Dictionary<string, string> environment;
        private bool systemRunning = true;

        public void Start()
        {
            InitializeSystem();
            Run();
        }

        private void InitializeSystem()
        {
            console = new ConsoleDriver();
            systemRoot = Path.Combine(Directory.GetCurrentDirectory(), "simpleos_root");

            console.Clear();
            console.WriteLine("=== SimpleOS Boot Sequence v3.7 ===");
            console.WriteLine("Initializing hardware... OK");
            console.WriteLine("Loading kernel modules... OK");
            console.WriteLine("Mounting file system... OK");
            fileSystem = new FileSystem(systemRoot);
            console.WriteLine("Loading user system... OK");
            userManager = new UserManager(systemRoot);
            console.WriteLine("Starting application manager... OK");
            appManager = new ApplicationManager();
            console.WriteLine("Initializing cache system... OK");
            cacheManager = new CacheManager();
            console.WriteLine("Loading translation service... OK");
            translation = new TranslationManager();
            console.WriteLine("Starting network services... OK");
            networkManager = new NetworkManager();
            console.WriteLine("Loading package manager... OK");
            packageManager = new PackageManager(systemRoot);
            console.WriteLine("Starting job manager... OK");
            jobManager = new BackgroundJobManager();
            console.WriteLine("Starting system monitor... OK");
            systemMonitor = new SystemMonitor();
            console.WriteLine("Initializing crypto services... OK");
            crypto = new SimpleCrypto();
            console.WriteLine("Initializing environment... OK");
            InitializeEnvironment();
            console.WriteLine("System ready!\n");
            Login();
        }

        private void InitializeEnvironment()
        {
            environment = new Dictionary<string, string>
            {
                ["LANG"] = currentLanguage,
                ["USER"] = "user",
                ["HOME"] = "/home/user",
                ["PATH"] = "/bin:/usr/bin:/usr/local/bin",
                ["PWD"] = currentDirectory,
                ["SHELL"] = "/bin/simpleos",
                ["TERM"] = "xterm-256color",
                ["EDITOR"] = "textedit",
                ["SIMPLEOS_VERSION"] = "3.7.0"
            };
        }

        private void Login()
        {
            console.WriteLine("=== SimpleOS Login ===");

            int attempts = 0;
            while (attempts < 3)
            {
                console.Write("Username: ");
                string username = console.ReadLine();
                console.Write("Password: ");
                string password = ReadPassword();

                currentUser = userManager.Authenticate(username, password);
                if (currentUser != null)
                {
                    // Загружаем язык пользователя
                    string userLang = userManager.GetUserLanguage(username);
                    if (!string.IsNullOrEmpty(userLang) && translation.IsLanguageSupported(userLang))
                        currentLanguage = userLang;

                    // Инициализируем кэш для пользователя
                    cacheManager.InitializeUserCache(username);

                    // Обновляем переменные окружения
                    environment["USER"] = username;
                    environment["HOME"] = currentUser.HomeDirectory;
                    environment["LANG"] = currentLanguage;
                    currentDirectory = currentUser.HomeDirectory;
                    environment["PWD"] = currentDirectory;

                    console.WriteLine("\n" + translation.Translate("login_successful", currentLanguage, username));
                    ShowWelcomeMessage();
                    return;
                }

                console.WriteLine("\n" + translation.Translate("login_failed", currentLanguage));
                attempts++;
            }

            console.WriteLine("Too many failed login attempts. System halted.");
            Environment.Exit(1);
        }

        private string ReadPassword()
        {
            StringBuilder password = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    Console.Write("\b \b");
                }
                else if (key.Key != ConsoleKey.Enter)
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            while (key.Key != ConsoleKey.Enter);

            return password.ToString();
        }

        private void ShowWelcomeMessage()
        {
            console.Clear();
            console.WriteLine("┌─────────────────────────────────────────────────────┐");
            console.WriteLine("│                   SimpleOS v3.7                     │");
            console.WriteLine("│               'Stable Release'                      │");
            console.WriteLine("├─────────────────────────────────────────────────────┤");
            console.WriteLine("│  Welcome, " + currentUser.Username.PadRight(40) + "│");
            console.WriteLine("│  User Type: " + currentUser.UserType.ToString().PadRight(36) + "│");
            console.WriteLine("│  Language: " + currentLanguage.PadRight(37) + "│");
            console.WriteLine("│                                                     │");
            console.WriteLine("│  New Features:                                      │");
            console.WriteLine("│  • Network Management                               │");
            console.WriteLine("│  • Package Management                               │");
            console.WriteLine("│  • Background Jobs                                  │");
            console.WriteLine("│  • File Encryption                                  │");
            console.WriteLine("│  • System Monitoring                                │");
            console.WriteLine("└─────────────────────────────────────────────────────┘");
            console.WriteLine(translation.Translate("type_help", currentLanguage));
            console.WriteLine();
        }

        private void Run()
        {
            while (systemRunning)
            {
                try
                {
                    ShowPrompt();
                    string input = console.ReadLine().Trim();

                    if (string.IsNullOrEmpty(input))
                        continue;

                    commandHistory.Add(input);
                    ProcessCommand(input);
                }
                catch (Exception ex)
                {
                    console.WriteLine($"System error: {ex.Message}");
                }
            }
        }

        private void ShowPrompt()
        {
            string prompt = $"{currentUser.Username}@{Environment.MachineName}:{currentDirectory}$ ";
            console.Write(prompt);
        }

        private void ProcessCommand(string input)
        {
            string[] parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return;

            string command = parts[0].ToLower();
            string[] args = parts.Length > 1 ? parts.Skip(1).ToArray() : new string[0];

            switch (command)
            {
                case "help":
                    ShowHelp();
                    break;
                case "clear":
                    console.Clear();
                    break;
                case "pwd":
                    console.WriteLine(currentDirectory);
                    break;
                case "ls":
                    ListDirectory(args.Length > 0 ? args[0] : currentDirectory);
                    break;
                case "cd":
                    ChangeDirectory(args.Length > 0 ? args[0] : "~");
                    break;
                case "cat":
                    if (args.Length > 0) ReadFile(args[0]);
                    break;
                case "echo":
                    console.WriteLine(string.Join(" ", args));
                    break;
                case "whoami":
                    console.WriteLine(currentUser.Username);
                    break;
                case "users":
                    ListUsers();
                    break;
                case "lang":
                    ChangeLanguage(args);
                    break;
                case "history":
                    ShowHistory();
                    break;
                case "exit":
                case "logout":
                    Logout();
                    break;
                case "shutdown":
                    Shutdown();
                    break;
                case "date":
                    console.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                    break;
                case "env":
                    ShowEnvironment();
                    break;
                case "setenv":
                    if (args.Length >= 2) SetEnvironmentVariable(args[0], args[1]);
                    break;
                case "cache":
                    ShowCacheInfo();
                    break;
                case "clearcache":
                    cacheManager.ClearCache();
                    break;
                case "network":
                    ShowNetworkInfo();
                    break;
                case "packages":
                    ManagePackages(args);
                    break;
                case "jobs":
                    ManageJobs(args);
                    break;
                case "encrypt":
                    if (args.Length >= 2) crypto.EncryptFile(args[0], args[1]);
                    break;
                case "decrypt":
                    if (args.Length >= 2) crypto.DecryptFile(args[0], args[1]);
                    break;
                case "monitor":
                    ShowSystemMonitor();
                    break;
                case "grep":
                    if (args.Length >= 2) SearchInFile(args[0], args[1]);
                    break;
                case "wc":
                    if (args.Length > 0) WordCount(args[0]);
                    break;
                case "mkdir":
                    if (args.Length > 0) CreateDirectory(args[0]);
                    break;
                case "touch":
                    if (args.Length > 0) CreateFile(args[0]);
                    break;
                case "rm":
                    if (args.Length > 0) DeleteFile(args[0]);
                    break;
                case "cp":
                    if (args.Length >= 2) CopyFile(args[0], args[1]);
                    break;
                case "mv":
                    if (args.Length >= 2) MoveFile(args[0], args[1]);
                    break;
                default:
                    // Проверяем, является ли команда приложением
                    if (appManager.IsApplication(command))
                    {
                        appManager.RunApplication(command, args);
                    }
                    else
                    {
                        console.WriteLine(translation.Translate("command_not_found", currentLanguage, command));
                    }
                    break;
            }
        }

        private void ShowHelp()
        {
            console.WriteLine(translation.Translate("available_commands", currentLanguage));
            console.WriteLine("=== Basic Commands ===");
            console.WriteLine("help, clear, exit, logout, shutdown, date, whoami");
            console.WriteLine("pwd, ls, cd, cat, echo, history");
            console.WriteLine("mkdir, touch, rm, cp, mv, grep, wc");

            console.WriteLine("\n=== User Management ===");
            console.WriteLine("users, lang");

            console.WriteLine("\n=== System Management ===");
            console.WriteLine("env, setenv, cache, clearcache, monitor");

            console.WriteLine("\n=== Network ===");
            console.WriteLine("network");

            console.WriteLine("\n=== Package Management ===");
            console.WriteLine("packages list, packages install <name>, packages remove <name>");
            console.WriteLine("packages search <query>, packages available");

            console.WriteLine("\n=== Background Jobs ===");
            console.WriteLine("jobs list, jobs start <command>, jobs kill <id>");

            console.WriteLine("\n=== Security ===");
            console.WriteLine("encrypt <file> <password>, decrypt <file> <password>");

            console.WriteLine("\n=== Applications ===");
            var apps = appManager.GetAvailableApplications();
            foreach (var app in apps)
            {
                console.WriteLine($"{app.Name} - {app.Description}");
            }
        }

        private void ListDirectory(string path)
        {
            try
            {
                string realPath = GetRealPath(path);

                if (Directory.Exists(realPath))
                {
                    var directories = Directory.GetDirectories(realPath);
                    var files = Directory.GetFiles(realPath);

                    console.WriteLine("Directories:");
                    foreach (var dir in directories)
                    {
                        string dirName = Path.GetFileName(dir);
                        console.WriteLine($"  📁 {dirName}");
                    }

                    console.WriteLine("\nFiles:");
                    foreach (var file in files)
                    {
                        string fileName = Path.GetFileName(file);
                        FileInfo info = new FileInfo(file);
                        console.WriteLine($"  📄 {fileName} ({info.Length} bytes)");
                    }
                }
                else
                {
                    console.WriteLine(translation.Translate("directory_not_found", currentLanguage, path));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void ChangeDirectory(string path)
        {
            try
            {
                string targetPath = path;

                if (path == "~")
                    targetPath = currentUser.HomeDirectory;
                else if (path == "..")
                    targetPath = Path.GetDirectoryName(currentDirectory) ?? "/";
                else if (!path.StartsWith("/"))
                    targetPath = Path.Combine(currentDirectory, path);

                string realPath = GetRealPath(targetPath);

                if (Directory.Exists(realPath))
                {
                    currentDirectory = fileSystem.GetVirtualPath(realPath);
                    environment["PWD"] = currentDirectory;
                }
                else
                {
                    console.WriteLine(translation.Translate("directory_not_found", currentLanguage, path));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void ReadFile(string filePath)
        {
            try
            {
                string realPath = GetRealPath(filePath);

                if (File.Exists(realPath))
                {
                    string content = File.ReadAllText(realPath);
                    console.WriteLine(content);

                    // Кэшируем файл
                    cacheManager.CacheFile(filePath, content);
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, filePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void ListUsers()
        {
            if (currentUser.UserType < UserType.Operator)
            {
                console.WriteLine(translation.Translate("permission_denied", currentLanguage));
                return;
            }

            var users = userManager.GetAllUsers();
            console.WriteLine($"Registered users ({users.Count}):");
            foreach (var user in users)
            {
                console.WriteLine($"  {user.Username} ({user.UserType}) - {user.HomeDirectory}");
            }
        }

        private void ChangeLanguage(string[] args)
        {
            if (args.Length == 0)
            {
                console.WriteLine($"Current language: {currentLanguage} ({translation.GetLanguageName(currentLanguage)})");
                console.WriteLine("Available languages: en, ru");
                return;
            }

            string newLang = args[0].ToLower();
            if (translation.IsLanguageSupported(newLang))
            {
                currentLanguage = newLang;
                environment["LANG"] = currentLanguage;
                userManager.SetUserLanguage(currentUser.Username, currentLanguage);
                console.WriteLine($"Language changed to {translation.GetLanguageName(currentLanguage)}");
            }
            else
            {
                console.WriteLine($"Language '{newLang}' is not supported");
            }
        }

        private void ShowHistory()
        {
            console.WriteLine("Command History:");
            for (int i = 0; i < commandHistory.Count; i++)
            {
                console.WriteLine($"{i + 1}: {commandHistory[i]}");
            }
        }

        private void Logout()
        {
            console.WriteLine(translation.Translate("logout_message", currentLanguage, currentUser.Username));
            Thread.Sleep(2000);
            console.Clear();
            Login();
        }

        private void Shutdown()
        {
            if (currentUser.UserType < UserType.Operator)
            {
                console.WriteLine(translation.Translate("permission_denied", currentLanguage));
                return;
            }

            console.WriteLine("Shutting down SimpleOS...");
            for (int i = 3; i > 0; i--)
            {
                console.WriteLine($"{i}...");
                Thread.Sleep(1000);
            }
            console.WriteLine("Goodbye!");
            systemRunning = false;
        }

        private void ShowEnvironment()
        {
            console.WriteLine("Environment Variables:");
            foreach (var variable in environment)
            {
                console.WriteLine($"  {variable.Key}={variable.Value}");
            }
        }

        private void SetEnvironmentVariable(string key, string value)
        {
            environment[key] = value;
            console.WriteLine($"Set {key}={value}");
        }

        private void ShowCacheInfo()
        {
            var stats = cacheManager.GetCacheStatistics();
            var cachedFiles = cacheManager.GetCachedFiles();

            console.WriteLine("=== Cache Statistics ===");
            console.WriteLine($"Total files: {stats.TotalFiles}");
            console.WriteLine($"Total size: {stats.TotalSize} bytes");
            console.WriteLine($"Hits: {stats.Hits}, Misses: {stats.Misses}");
            console.WriteLine($"Hit ratio: {stats.HitRatio:P2}");

            if (cachedFiles.Count > 0)
            {
                console.WriteLine("\nCached Files:");
                foreach (var file in cachedFiles)
                {
                    console.WriteLine($"  {file.FilePath} (v{file.Version}, {file.AccessCount} accesses)");
                }
            }
        }

        private void ShowNetworkInfo()
        {
            console.WriteLine("=== Network Status ===");
            console.WriteLine($"Status: {networkManager.Status}");

            console.WriteLine("\nNetwork Interfaces:");
            var interfaces = networkManager.GetNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                console.WriteLine($"  {iface.Name}: {iface.IP} [{iface.Status}]");
            }

            console.WriteLine("\nActive Connections:");
            var connections = networkManager.GetActiveConnections();
            foreach (var conn in connections)
            {
                console.WriteLine($"  {conn.Protocol}: {conn.Local} -> {conn.Remote} [{conn.State}]");
            }
        }

        private void ManagePackages(string[] args)
        {
            if (args.Length == 0)
            {
                console.WriteLine("Usage: packages <list|install|remove|search|available>");
                return;
            }

            string subcommand = args[0].ToLower();

            switch (subcommand)
            {
                case "list":
                    var installed = packageManager.GetInstalledPackages();
                    console.WriteLine("Installed packages:");
                    foreach (var pkg in installed)
                    {
                        console.WriteLine($"  {pkg.Name} ({pkg.Version}) - {pkg.Description}");
                    }
                    break;

                case "install":
                    if (args.Length >= 2)
                        packageManager.InstallPackage(args[1]);
                    else
                        console.WriteLine("Usage: packages install <package-name>");
                    break;

                case "remove":
                    if (args.Length >= 2)
                        packageManager.RemovePackage(args[1]);
                    else
                        console.WriteLine("Usage: packages remove <package-name>");
                    break;

                case "search":
                    if (args.Length >= 2)
                        packageManager.SearchPackages(args[1]);
                    else
                        console.WriteLine("Usage: packages search <query>");
                    break;

                case "available":
                    var available = packageManager.GetAvailablePackages();
                    console.WriteLine("Available packages:");
                    foreach (var pkg in available)
                    {
                        console.WriteLine($"  {pkg.Name} ({pkg.Version}) - {pkg.Description} ({pkg.Size} bytes)");
                    }
                    break;

                default:
                    console.WriteLine($"Unknown package command: {subcommand}");
                    break;
            }
        }

        private void ManageJobs(string[] args)
        {
            if (args.Length == 0)
            {
                console.WriteLine("Usage: jobs <list|start|kill>");
                return;
            }

            string subcommand = args[0].ToLower();

            switch (subcommand)
            {
                case "list":
                    var jobs = jobManager.GetJobs();
                    console.WriteLine("Background Jobs:");
                    foreach (var job in jobs)
                    {
                        console.WriteLine($"  [{job.Id}] {job.Command} - {job.Status} ({job.Progress}%)");
                    }
                    break;

                case "start":
                    if (args.Length >= 2)
                    {
                        var command = string.Join(" ", args.Skip(1));
                        var job = jobManager.StartJob(command);
                        console.WriteLine($"Started job [{job.Id}]: {command}");
                    }
                    else
                    {
                        console.WriteLine("Usage: jobs start <command>");
                    }
                    break;

                case "kill":
                    if (args.Length >= 2 && int.TryParse(args[1], out int jobId))
                    {
                        if (jobManager.KillJob(jobId))
                            console.WriteLine($"Job [{jobId}] terminated");
                        else
                            console.WriteLine($"Failed to terminate job [{jobId}]");
                    }
                    else
                    {
                        console.WriteLine("Usage: jobs kill <job-id>");
                    }
                    break;

                default:
                    console.WriteLine($"Unknown jobs command: {subcommand}");
                    break;
            }
        }

        private void ShowSystemMonitor()
        {
            var sysInfo = systemMonitor.GetSystemInfo();
            var processes = systemMonitor.GetRunningProcesses();

            console.WriteLine("=== System Monitor ===");
            console.WriteLine($"Uptime: {sysInfo.Uptime:hh\\:mm\\:ss}");
            console.WriteLine($"Memory: {sysInfo.MemoryUsage / 1024 / 1024} MB / {sysInfo.TotalMemory / 1024 / 1024} MB");
            console.WriteLine($"CPU Time: {sysInfo.CpuUsage:c}");
            console.WriteLine($"Threads: {sysInfo.ThreadCount}");
            console.WriteLine($"Disk: {sysInfo.DiskFree / 1024 / 1024} MB free of {sysInfo.DiskTotal / 1024 / 1024} MB");

            console.WriteLine("\nRunning Processes:");
            console.WriteLine("PID\tName\t\tCPU\tMemory\tStatus");
            foreach (var proc in processes)
            {
                console.WriteLine($"{proc.PID}\t{proc.Name}\t\t{proc.CPU:F1}\t{proc.Memory} KB\t{proc.Status}");
            }
        }

        private void SearchInFile(string filePath, string pattern)
        {
            try
            {
                string realPath = GetRealPath(filePath);

                if (File.Exists(realPath))
                {
                    string[] lines = File.ReadAllLines(realPath);
                    for (int i = 0; i < lines.Length; i++)
                    {
                        if (lines[i].Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            console.WriteLine($"{i + 1}: {lines[i]}");
                        }
                    }
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, filePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void WordCount(string filePath)
        {
            try
            {
                string realPath = GetRealPath(filePath);

                if (File.Exists(realPath))
                {
                    string content = File.ReadAllText(realPath);
                    int lines = content.Split('\n').Length;
                    int words = content.Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries).Length;
                    int characters = content.Length;
                    int bytes = System.Text.Encoding.UTF8.GetByteCount(content);

                    console.WriteLine($"  {lines}  {words}  {characters}  {bytes} {filePath}");
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, filePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void CreateDirectory(string dirPath)
        {
            try
            {
                string realPath = GetRealPath(dirPath);
                Directory.CreateDirectory(realPath);
                console.WriteLine($"Directory created: {dirPath}");
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void CreateFile(string filePath)
        {
            try
            {
                string realPath = GetRealPath(filePath);
                File.WriteAllText(realPath, "");
                console.WriteLine($"File created: {filePath}");
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void DeleteFile(string filePath)
        {
            try
            {
                string realPath = GetRealPath(filePath);

                if (File.Exists(realPath))
                {
                    File.Delete(realPath);
                    console.WriteLine($"File deleted: {filePath}");
                }
                else if (Directory.Exists(realPath))
                {
                    Directory.Delete(realPath, true);
                    console.WriteLine($"Directory deleted: {filePath}");
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, filePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void CopyFile(string sourcePath, string destPath)
        {
            try
            {
                string realSourcePath = GetRealPath(sourcePath);
                string realDestPath = GetRealPath(destPath);

                if (File.Exists(realSourcePath))
                {
                    File.Copy(realSourcePath, realDestPath, true);
                    console.WriteLine($"Copied: {sourcePath} -> {destPath}");
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, sourcePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private void MoveFile(string sourcePath, string destPath)
        {
            try
            {
                string realSourcePath = GetRealPath(sourcePath);
                string realDestPath = GetRealPath(destPath);

                if (File.Exists(realSourcePath))
                {
                    File.Move(realSourcePath, realDestPath);
                    console.WriteLine($"Moved: {sourcePath} -> {destPath}");
                }
                else
                {
                    console.WriteLine(translation.Translate("file_not_found", currentLanguage, sourcePath));
                }
            }
            catch (Exception ex)
            {
                console.WriteLine($"Error: {ex.Message}");
            }
        }

        private string GetRealPath(string virtualPath)
        {
            if (virtualPath.StartsWith("/"))
                return fileSystem.GetRealPath(virtualPath);
            else
                return fileSystem.GetRealPath(Path.Combine(currentDirectory, virtualPath));
        }
    }
}