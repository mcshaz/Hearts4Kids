﻿using Hearts4Kids.Services;
using MvcFileUploader;
using MvcFileUploader.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Hearts4Kids.Controllers
{
    [Authorize]
    public class GalleryController : Controller
    {
        // GET: Gallery
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View(PhotoServices.GetImages());
        }
        [Authorize(Roles =Domain.Admin)]
        public ActionResult MakeBanner()
        {
            return View(PhotoServices.GetImages());
        }
        [Authorize(Roles =Domain.Admin), HttpPost, ValidateAntiForgeryToken]
        public ActionResult MakeBanner(string[] forBanner)
        {
            PhotoServices.makeBanner(forBanner);
            return RedirectToAction("Index","Home");
        }
        public ActionResult Upload()
        {
            return View();
        }
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult UploadFile(int? entityId) // optionally receive values specified with Html helper
        {
            // here we can send in some extra info to be included with the delete url 
            var statuses = new List<ViewDataUploadFileResult>();
            string initialDir = PhotoServices.GetDefaultDir();
            for (var i = 0; i < Request.Files.Count; i++)
            {
                var st = FileSaver.StoreFile(x =>
                {
                    x.File = Request.Files[i];
                    //note how we are adding an additional value to be posted with delete request
                    //and giving it the same value posted with upload
                    x.DeleteUrl = Url.Action("DeleteFile", new { entityId = entityId });
                    x.StorageDirectory = initialDir;
                    //x.UrlPrefix = "/Content/uploads";// this is used to generate the relative url of the file

                    //overriding defaults
                    x.FileName = Request.Files[i].FileName;// default is filename suffixed with filetimestamp
                    //x.ThrowExceptions = true;//default is false, if false exception message is set in error property
                });
                st.thumbnailUrl = PhotoServices.processImage(st.SavedFileName).Substring(1); //hack
                statuses.Add(st);
            }

            //statuses contains all the uploaded files details (if error occurs then check error property is not null or empty)
            //todo: add additional code to generate thumbnail for videos, associate files with entities etc

            //adding thumbnail url for jquery file upload javascript plugin
            //statuses.ForEach(x => x.thumbnailUrl = x.url); // uses ImageResizer httpmodule to resize images from this url

            //setting custom download url instead of direct url to file which is default
            //statuses.ForEach(x => x.url = Url.Action("DownloadFile", new { fileUrl = x.url, mimetype = x.type }));

            var viewresult = Json(new { files = statuses });
            //for IE8 which does not accept application/json
            if (Request.Headers["Accept"] != null && !Request.Headers["Accept"].Contains("application/json"))
                viewresult.ContentType = "text/plain";

            return viewresult;
        }





        //here i am receving the extra info injected
        [HttpPost, ValidateAntiForgeryToken] // should accept only post
        public ActionResult DeleteFile(int? entityId, string fileUrl)
        {
            PhotoServices.DeleteImages(fileUrl);

            var viewresult = Json(new { error = String.Empty });
            //for IE8 which does not accept application/json
            if (Request.Headers["Accept"] != null && !Request.Headers["Accept"].Contains("application/json"))
                viewresult.ContentType = "text/plain";

            return viewresult; // trigger success
        }


        public ActionResult DownloadFile(string fileUrl, string mimetype)
        {
            var filePath = Server.MapPath("~" + fileUrl);

            if (System.IO.File.Exists(filePath))
                return File(filePath, mimetype);
            else
            {
                return new HttpNotFoundResult("File not found");
            }
        }
    }
}