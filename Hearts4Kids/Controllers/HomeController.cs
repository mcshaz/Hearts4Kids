using System.Web.Mvc;
using System.Data;
using Hearts4Kids.Models;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Hearts4Kids.Services;
using Hearts4Kids.Extensions;
using System;

namespace Hearts4Kids.Controllers
{
    public class HomeController : BaseUserController
    {
        public ActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> Team()
        {
            var model = await MemberDetailServices.GetBiosForDisplay(true);
            return View(model);
        }

        public ActionResult About()
        {
            return View();
        }

        public ActionResult Donate()
        {
            return View();
        }
        [HttpPost]
        public async Task<ActionResult> Subscribe(SubscribeModel subscriberMail)
        {
            var res = await SubscriberServices.AddEmail(subscriberMail, true);
            return new JsonResult{ Data = res.ToString().SplitCamelCase() };
        }

        public ActionResult FAQ()
        {
            ViewBag.Message = "Your frequently asked Questions page.";

            return View();
        }

        public ActionResult Sponsors()
        {
            return View();
        }

        public async Task<ActionResult> YouthVolunteers()
        {
            var model = await MemberDetailServices.GetStudents();
            return View(model);
        }

        public ActionResult Contact(int? id=null)
        {
            return View(new ContactViewModel { ContactId = id });
        }

        public ActionResult Background()
        {
            return View();
        }

        public ActionResult Success()
        {
            return View();
        }

        public ActionResult DisplayPdf(string id)
        {
            ViewBag.Source = "/Content/PublicPdfs/" + id + ".pdf";
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ContactSubmit(
            [Bind(Include = "FromName, FromEmail, FromPhone, Message, ContactId")]
            ContactViewModel model)
        {
            try
            {
                if (!await RecaptchaServices.Validate(Request))
                {
                    ModelState.AddModelError(string.Empty, "You have not confirmed that you are not a robot");
                }
                if (ModelState.IsValid)
                {
                    const string body = "<p>Email From: {0} ({1}) Ph: {2}</p><p>Message:</p><p>{3}</p>";
                    var msg = new IdentityMessage
                    {
                        Body = string.Format(body, model.FromName, model.FromEmail, model.FromPhone, model.Message),
                        Subject = "H4K Web form Message"
                    };
                    if (model.ContactId.HasValue)
                    {
                        var usr = await UserManager.FindByIdAsync(model.ContactId.Value);
                        if (usr == null) { throw new System.Exception("Unknown User Id"); }
                        var client = new System.Net.Mail.SmtpClient();
                        client.SendCompleted += (s, e) => {
                            client.Dispose();
                        };
                        var mail = new System.Net.Mail.MailMessage
                        {
                            Subject = msg.Subject, Body = msg.Body, IsBodyHtml = true
                        };
                        mail.To.Add(usr.Email);
                        await client.SendMailAsync(mail); 
                    }
                    else
                    {
                        await SendEmailsToRoleAsync(Domain.DomainConstants.Admin, msg);
                    }
                    return RedirectToAction("Success");
                }
            }
            catch (DataException ex/* dex */)
            {
                ModelState.AddModelError("", "Unable to send message. Please try again later.");
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex);
                model.Success = false;
                return View("Contact", model);
            }

            return View("Contact", model);
        }
    }
}