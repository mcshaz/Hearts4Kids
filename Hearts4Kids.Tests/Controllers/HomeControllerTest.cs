using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Hearts4Kids;
using Hearts4Kids.Controllers;
using Hearts4Kids.Models;

namespace Hearts4Kids.Tests.Controllers
{
    [TestClass]
    public sealed class HomeControllerTest
    {
        private HomeController _controller;
        private HomeController Controller
        {
            get { return _controller ?? (_controller = new HomeController()); }
        }
        [TestMethod]
        public void Index()
        {
            // Act
            ViewResult result = Controller.Index() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public void About()
        {
            // Act
            ViewResult result = Controller.About() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            //Assert.AreEqual("Your application description page.", result.ViewBag.Message);
        }

        [TestMethod]
        public void Contact()
        { 
            // Act
            ViewResult result = Controller.Contact() as ViewResult;

            // Assert
            Assert.IsNotNull(result);

            //return View(new ContactViewModel { ContactId = id });
        }

        [TestMethod]
        public async void Team()
        {
            // Act
            ViewResult result = await Controller.Team() as ViewResult;

            // Assert
            Assert.IsNotNull(result);

            //var model = MemberDetailServices.GetBiosForDisplay(true);
        }

        [TestMethod]
        public void Donate()
        {
            // Act
            ViewResult result = Controller.Donate() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async void Subscribe()
        {
            SubscribeModel subscriberMail = new SubscribeModel
            {
                Email = "example@example.com",
                Fundraisers = true,
                Newsletter = true
            };

            ViewResult result = await Controller.Subscribe(subscriberMail) as ViewResult;

            Assert.IsNotNull(result);

            //var res = await SubscriberServices.AddEmail(subscriberMail, true);
            //return new JsonResult { Data = res.ToString().SplitCamelCase() };
        }

        [TestMethod]
        public void FAQ()
        {
            // Act
            ViewResult result = Controller.FAQ() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public void Sponsors()
        {
            // Act
            ViewResult result = Controller.Sponsors() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async void YouthVolunteers()
        {
            // Act
            ViewResult result = await Controller.YouthVolunteers() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            //var model = await MemberDetailServices.GetStudents();
        }

        [TestMethod]
        public void Background()
        {
            // Act
            ViewResult result = Controller.Background() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public void Success()
        {
            // Act
            ViewResult result = Controller.Success() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        /*
         * TODO
        public ActionResult DisplayPdf(string id)
        {
            ViewBag.Source = "/Content/PublicPdfs/" + id + ".pdf";
            return View();
        }
        */

        [TestMethod]
        public async void ContactSubmit()
        {
            ContactViewModel model = new ContactViewModel
            {
                FromEmail = "example@example.com",
                FromName = "example",
                Message = "test message"
            };

            ViewResult result = await Controller.ContactSubmit(model) as ViewResult;
            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(0, Controller.ModelState.Count);

            Assert.IsInstanceOfType(result, typeof(RedirectToRouteResult));

            model.Success = false;
            model.FromEmail = "dr@rd";
            result = await Controller.ContactSubmit(model) as ViewResult;
            Assert.AreEqual(1, Controller.ModelState.Count);
        }

        ~HomeControllerTest()
        {
            if (_controller != null)
            {
                _controller.Dispose();
            }
        }
    }
}
