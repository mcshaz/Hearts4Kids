using System.Collections.Generic;
using System.Web.Hosting;
using System.Linq;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System;
using Hearts4Kids.Models;
using System.IO;
using System.Web;
using System.Text.RegularExpressions;

namespace Hearts4Kids.Services
{
    public static class PhotoServices
    {
        public const string bioDir = "~/Content/Photos/Bios";
        public const string logoDir = "~/Content/Logos";
        public const int maxHeight = 696;
        public const int thumbHeight = 76;
        public const int bannerHeight = 232;
        public const long defaultQuality = 98;
        //screen * md-7 = 7/12
        public const int maxBannerWidth = 1600 * 7 / 12;
        public const string defaultDir = "~/Content/Photos/Slides";
        public const string bannerPath = "~/Content/Photos/Banner.jpg";
        internal class SiteImageSize
        {
            public SiteImageSize(string folderName, int height)
            {
                FolderName = folderName;
                Height = height;
                Quality = defaultQuality;
            }
            public string FolderName { get; private set; }
            public int Height { get; private set; }
            public ImageFormat ImgFmt { get; set; }
            public long Quality { get; set; }
            public string GetFileNameWithExt(string originalFileName)
            {
                string newExt;
                if (ImgFmt == ImageFormat.Bmp)
                {
                    newExt = "bmp";
                }
                else if (ImgFmt == ImageFormat.Jpeg)
                {
                    newExt = "jpg";
                }
                else if (ImgFmt == ImageFormat.Png)
                {
                    newExt = "png";
                }
                else if (ImgFmt == ImageFormat.Tiff)
                {
                    newExt = "tiff";
                }
                else if (ImgFmt == ImageFormat.Icon)
                {
                    newExt = "icon";
                }
                else
                {
                    throw new Exception("unsupported type");
                }
                return Path.ChangeExtension(originalFileName, newExt);
            }
        }
        internal static SiteImageSize[] ImageSizes = new SiteImageSize[]
        {
            new SiteImageSize ( "lg", maxHeight) { ImgFmt=ImageFormat.Jpeg }, //936
            new SiteImageSize ( "pv", bannerHeight) { ImgFmt=ImageFormat.Png }, //312
            new SiteImageSize ( "th", thumbHeight) { ImgFmt=ImageFormat.Png } //104
        };
        public static string GetDefaultDir()
        {
            return Path.Combine(HostingEnvironment.MapPath(defaultDir), ImageSizes[0].FolderName);
        }
        public static string ProcessLogo(HttpPostedFileBase file)
        {
            string basePath = HostingEnvironment.MapPath(logoDir);
            var newSize = ImageSizes[1];
            string newFileName = newSize.GetFileNameWithExt(file.FileName);
            ResizeImg(file, newSize, Path.Combine(basePath, newFileName));
            return logoDir + '/' + newFileName;
        }
        public static string ProcessBioImage(HttpPostedFileBase file)
        {
            string basePath = HostingEnvironment.MapPath(defaultDir);
            var newSize = ImageSizes[0];
            string newFileName = GetBioFileName(newSize.GetFileNameWithExt(file.FileName));
            //multiResizeImage(file, newSize, basePath, newFileName);
            MultiResizeImage(file, newSize, basePath, newFileName);
            var returnSize = ImageSizes[1];
            return defaultDir + '/' + returnSize.FolderName + '/' + GetBioFileName(returnSize.GetFileNameWithExt(file.FileName));
        }
        const string bioPrefix = "bio_";
        static string GetBioFileName(string fileName)
        {
            return  bioPrefix + fileName;
        }
        static void ResizeImg(HttpPostedFileBase file, SiteImageSize newSize, string serverPath)
        {
            using (var srcImage = Image.FromStream(file.InputStream))
            {
                Resize(srcImage, serverPath, newSize.Height, newSize.ImgFmt, newSize.Quality);
            }
        }
        internal static string MultiResizeImage(HttpPostedFileBase file, SiteImageSize newSize, string basePath, string newFileName)
        {
            ResizeImg(file, newSize, Path.Combine(basePath, newSize.FolderName, newFileName));
            return MultiResizeImage(newFileName);
        }

        /// <summary>
        /// makes various sizes, added to appropriate folders, and returns the full path to the thumbnail
        /// </summary>
        /// <param name="imageName"></param>
        /// <param name="virtualPath"></param>
        public static string MultiResizeImage(string imageName, string virtualPath= defaultDir)
        {
            string basePath = HostingEnvironment.MapPath(virtualPath);
            string path = Path.Combine(basePath, ImageSizes[0].FolderName,imageName);
            SiteImageSize s=null;
            string newFileName = null;
            for(int i=1;i < ImageSizes.Length;i++)
            {
                s = ImageSizes[i];
                newFileName = s.GetFileNameWithExt(imageName);
                Resize(path, Path.Combine(basePath, s.FolderName, newFileName), s.Height, s.ImgFmt, s.Quality);
            }
            return defaultDir + '/' + s.FolderName + '/' + newFileName;
        }
        public static IEnumerable<GalleryModel> GetImages()
        {
            string[] imgExt = GetImgExt();
            string baseUr = defaultDir.Substring(1) + '/';//hack
            string fullUr = baseUr + ImageSizes[0].FolderName +'/';
            SiteImageSize thumb = ImageSizes[ImageSizes.Length - 1];
            string thumbUr = baseUr + thumb.FolderName +'/';

            return (from p in Directory.EnumerateFiles(Path.Combine(HostingEnvironment.MapPath(defaultDir), ImageSizes[0].FolderName), "*", SearchOption.TopDirectoryOnly)
                    let fn = Path.GetFileName(p)
                    where !fn.StartsWith(bioPrefix) && imgExt.Any(e=>p.EndsWith(e, StringComparison.InvariantCultureIgnoreCase))
                    let fne = fn.Replace(" ","%20")
                    select new GalleryModel
                    {
                        url = fullUr + fne,
                        thumbnailUrl = thumbUr + thumb.GetFileNameWithExt(fne)
                    });
        }
        static string[] GetImgExt() { return new string[] { ".jpg", ".jpeg", ".png", ".bmp" }; }

        public static IEnumerable<AdminGalleryModel> GetAdminImages()
        {
            string[] imgExt = GetImgExt();
            string baseUr = defaultDir.Substring(1) + '/';//hack
            string fullUr = baseUr + ImageSizes[0].FolderName + '/';
            SiteImageSize thumb = ImageSizes[ImageSizes.Length - 1];
            string thumbUr = baseUr + thumb.FolderName + '/';
            DirectoryInfo di = new DirectoryInfo(Path.Combine(HostingEnvironment.MapPath(defaultDir), ImageSizes[0].FolderName));
            return (from p in di.EnumerateFiles("*", SearchOption.TopDirectoryOnly)
                    where !p.Name.StartsWith(bioPrefix) && imgExt.Any(e => string.Equals(p.Extension, e, StringComparison.InvariantCultureIgnoreCase))
                    select new AdminGalleryModel
                    {
                        url = fullUr + p.Name,
                        thumbnailUrl = thumbUr + thumb.GetFileNameWithExt(p.Name),
                        size = p.Length,
                        name = p.Name,
                        //type = p.Extension == ".jpg" ? "image/jpeg" : ("image/" + p.Extension.Substring(1))
                        
                    });
        }
        public static void Resize(string imageFile, string outputFile, int newHeight, ImageFormat fmt = null, long quality = defaultQuality)
        {
            using (var srcImage = Image.FromFile(imageFile))
            {
                Resize(srcImage, outputFile, newHeight, fmt, quality);
            }
        }
        public static void Resize(Image srcImage, string outputFile, int newHeight, ImageFormat fmt = null, long quality= defaultQuality)
        {
            int newWidth = newHeight * srcImage.Width / srcImage.Height;
            using (var newImage = new Bitmap(newWidth, newHeight))
            using (var graphics = Graphics.FromImage(newImage))
            {
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
                graphics.DrawImage(srcImage, new Rectangle(0, 0, newWidth, newHeight));
                if (fmt == null) { fmt = srcImage.RawFormat; }
                if (fmt != ImageFormat.Jpeg)
                {
                    newImage.Save(outputFile, fmt);
                }
                else
                {
                    // https://msdn.microsoft.com/en-us/library/bb882583%28v=vs.110%29.aspx
                    ImageCodecInfo jpgEncoder = GetEncoder(ImageFormat.Jpeg);

                    // Create an Encoder object based on the GUID 
                    // for the Quality parameter category.
                    System.Drawing.Imaging.Encoder myEncoder = System.Drawing.Imaging.Encoder.Quality;

                    // Create an EncoderParameters object. 
                    // An EncoderParameters object has an array of EncoderParameter 
                    // objects. In this case, there is only one 
                    // EncoderParameter object in the array.
                    EncoderParameters myEncoderParameters = new EncoderParameters(1);

                    EncoderParameter myEncoderParameter = new EncoderParameter(myEncoder, quality);
                    myEncoderParameters.Param[0] = myEncoderParameter;

                    newImage.Save(outputFile, jpgEncoder, myEncoderParameters);
                }
                
            }
        }
        private static ImageCodecInfo GetEncoder(ImageFormat format)
        {

            ImageCodecInfo[] codecs = ImageCodecInfo.GetImageDecoders();

            foreach (ImageCodecInfo codec in codecs)
            {
                if (codec.FormatID == format.Guid)
                {
                    return codec;
                }
            }
            return null;
        }
        public static void DeleteImages(string fileName, string baseDir = defaultDir)
        {
            string dirPath = HostingEnvironment.MapPath(baseDir);
            int start = fileName.LastIndexOf('/') + 1;
            int finish = fileName.LastIndexOf('.');
            fileName = fileName.Substring(start,finish-start) + ".*";
            foreach(var c in ImageSizes)
            {
                var dir = new DirectoryInfo(Path.Combine(dirPath, c.FolderName));
                foreach (var file in dir.EnumerateFiles(fileName))
                try
                {
                    file.Delete();
                }
                catch (IOException ex)
                {
                    Elmah.ErrorSignal.FromCurrentContext().Raise(ex);
                }
            }
        }
        public static void MakeBanner(IEnumerable<string> imageNames)
        {
            string dir = Path.Combine(HostingEnvironment.MapPath(defaultDir), ImageSizes[1].FolderName);
            IList<string> fns = imageNames.Select(i => {
                    var d = HttpUtility.UrlDecode(i);
                    return dir + '\\' + d.Substring(d.LastIndexOf('/') + 1);
                }).ToList();
            using (var bm = CombineBitmap(fns))
            {
                bm.Save(HostingEnvironment.MapPath(bannerPath), ImageFormat.Jpeg);
                //Resize(bm,bannerPath, bannerHeight,ImageFormat.Jpeg);
            }
            BannerUpdated = DateTime.Now;
                
        }
        public static Bitmap CombineBitmap(IList<string> files)
        {
            for(int i=0;i<files.Count;i++)
            {
                if (!File.Exists(files[i]))
                {
                    if (Path.GetExtension(files[i]).Equals(".png", StringComparison.InvariantCultureIgnoreCase))
                    {
                        files[i] = Path.ChangeExtension(files[i], ".jpg");
                    }else
                    {
                        files[i] = Path.ChangeExtension(files[i], ".png");
                    }
                    if (!File.Exists(files[i]))
                    {
                        throw new ArgumentException("File " + files[i] + "does not exist");
                    }
                        
                }
            }
            //read all images into memory
            List<Bitmap> images = new List<Bitmap>();
            Bitmap finalImage = null;

            try
            {
                int width = 0;
                int height = 0;

                foreach (string image in files)
                {
                    //create a Bitmap from the file and add it to the list
                    Bitmap bitmap = new Bitmap(image);

                    //update the size of the final bitmap
                    width += bitmap.Width;
                    height = bitmap.Height > height ? bitmap.Height : height;

                    images.Add(bitmap);
                }
                int imagesSupplied = images.Count;
                if (imagesSupplied == 0) { return null; }
                int pullLeft = width;
                int minFinalWidth = width + maxBannerWidth;
                int i = 0;

                do
                {
                    images.Add(images[i]);
                    width += images[i].Width;
                    if (++i >= imagesSupplied) { i = 0; }
                } while (width < minFinalWidth);

                //create a bitmap to hold the combined image
                finalImage = new Bitmap(width, height);

                //get a graphics object from the image so we can draw on it
                using (Graphics g = Graphics.FromImage(finalImage))
                {
                    //set background color
                    g.Clear(Color.Black);

                    //go through each image and draw it on the final image
                    int offset = 0;
                    foreach (Bitmap image in images)
                    {
                        g.DrawImage(image,
                          new System.Drawing.Rectangle(offset, 0, image.Width, image.Height));
                        offset += image.Width;
                    }
                }

                AlterCss(pullLeft, width);

                return finalImage;
            }
            catch (Exception)
            {
                if (finalImage != null)
                    finalImage.Dispose();

                throw;
            }
            finally
            {
                //clean up memory
                foreach (Bitmap image in images)
                {
                    image.Dispose();
                }
            }
        }
        private static void AlterCss(int pullLeft, int width)
        {
            var cssFile = HostingEnvironment.MapPath("~/Content/LandingPage.css");
            bool isDiv=false;
            string widthStr = string.Format("width:{0}px;", width);
            string translateStr = string.Format("translateX(-{0}px)", pullLeft);
            var bannerImage = $"background-image: url(\"/Content/Photos/Banner.jpg?{DateTime.UtcNow:s}\");";
            ApplyConversionToFile(cssFile, str => {
                    if (isDiv)
                    {
                        if (str.Contains('}'))
                        {
                            isDiv = false;
                        }
                        var returnString = Regex.Replace(str, @"width:\s*.*;", widthStr);
                        return Regex.Replace(returnString, "background-image:\\s*url\\(\"/Content/Photos/Banner\\.jpg\\??[0-9\\-T:Z]*\"\\);", bannerImage);
                    }
                    else
                    {
                        isDiv = Regex.IsMatch(str, @"\.photoContainer\s+div.photobanner\s*{");
                        if (isDiv) { return str; }
                        return Regex.Replace(str, @"translateX\s*\(-.*\)",translateStr);
                    }
                });
        }
        private static void ApplyConversionToFile(string filename, Func<string,string> convert)
        {
            string temp = Path.GetTempFileName();
            using (StreamReader sr = new StreamReader(File.Open(filename, FileMode.Open)))
            {
                using (StreamWriter sw = new StreamWriter(File.Open(temp, FileMode.Append)))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        sw.WriteLine(convert(line));
                    }
                }
            }

            File.Delete(filename);
            File.Move(temp, filename);
        }
        private static DateTime _bannerUpdated;
        internal static DateTime BannerUpdated
        {
            get
            {
                if (_bannerUpdated == default(DateTime))
                {
                    var path = HostingEnvironment.MapPath(bannerPath);
                    _bannerUpdated = File.GetCreationTime(path);
                }
                return _bannerUpdated;
            }
            private set
            {
                _bannerUpdated = value;
            }
        }
    }
}