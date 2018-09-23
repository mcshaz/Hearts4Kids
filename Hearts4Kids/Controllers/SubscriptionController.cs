using Hearts4Kids.Models;
using Hearts4Kids.Services;
using Mvc.JQuery.DataTables;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using static Hearts4Kids.Domain.DomainConstants;

namespace Hearts4Kids.Controllers
{
    public class SubscriptionController : BaseUserController
    {
        // GET: Subscription

        public async Task<ActionResult> Unsubscribe(int subscriberId, Guid code, SubscriptionTypes subscribeType)
        {
            var model = new ChangeSubscriptionModel
            {
                Success = await SubscriberServices.Unsubscribe(subscriberId, code, subscribeType),
                CurrentSubscription = subscribeType
            };
            
            return View(model);
        }
        [Authorize(Roles=Admin)]
        public ActionResult CreateReceipt()
        {
            return View(GetNewReceiptModel());
        }
        [Authorize(Roles = Admin), HttpPost, ValidateAntiForgeryToken]
        public async Task<ActionResult> CreateReceipt(ReceiptModel model, HttpPostedFileBase logoImg=null)
        {
            if (ModelState.IsValid)
            {
                if (logoImg != null)
                {
                    model.LogoSrc = PhotoServices.ProcessLogo(logoImg);
                }
                await ReceiptServices.CreateReceipt(model, ModelState, (subscriberId, code, subscriptionType) =>
                     Url.Action("Unsubscribe", "Subscription", new { subscriberId, code, subscriptionType }, protocol: Request.Url.Scheme));
                if (ModelState.IsValid)
                {
                    ModelState.Clear();
                    ViewBag.SuccessMsg = "Successfuly created and emailed receipt for " + model.Email;
                    return View(GetNewReceiptModel());
                }
            }
            return View(model);
        }
        [Authorize(Roles = Admin),HttpPost, ValidateAntiForgeryToken]
        public async Task<JsonResult> GetEmails(string startsWith)
        {
            return new JsonResult { Data = await SubscriberServices.GetEmails(startsWith) };
        }

        [Authorize(Roles = Admin), HttpPost, ValidateAntiForgeryToken]
        public async Task<JsonResult> GetDonorInfo(string email)
        {
            return new JsonResult { Data = await SubscriberServices.GetDonorInfo(email) };
        }
        [Authorize(Roles = Admin),HttpGet]
        public ViewResult AllReceipts()
        {
            return View();
        }
        [Authorize(Roles =Admin),HttpPost /*, ValidateAntiForgeryToken*/]
        public DataTablesResult<DonorListItemModel> GetDonations(DataTablesParam dataTableParam)
        {
            using (var db = new Domain.Hearts4KidsEntities())
            {
                return DataTablesResult.Create(
                    db.Receipts.Select(src => new DonorListItemModel
                    {
                        ReceiptNo = src.Id,
                        Amount = src.Amount,
                        Description = src.Description,
                        DateReceived = src.DateReceived,
                        ReceiptDate = src.DateSent,
                        Name = (src.NewsletterSubscriber != null) ? src.NewsletterSubscriber.Name
                            : (src.AspNetUser.UserBio.FirstName + " " + src.AspNetUser.UserBio.Surname),
                        Email = (src.NewsletterSubscriber != null) ? src.NewsletterSubscriber.Email : src.AspNetUser.Email,
                        TransferMethod = src.TransferMethod
                    }),
                    dataTableParam,
                    uv => new { DateReceived = uv.DateReceived.ToString("dd/MM/yyyy"),
                                ReceiptDate = uv.ReceiptDate.ToString("dd/MM/yyyy HH:mm"),
                                Amount = uv.Amount.ToString("c")
                              });
            }
        }
        public ActionResult UploadGiveALittleDonors()
        {
            return View();
        }
        [Authorize(Roles = Admin), HttpPost, ValidateAntiForgeryToken]
        public async Task<ActionResult> UploadGiveALittleDonors(HttpPostedFileBase spreadsheet)
        {
            if (spreadsheet == null)
            {
                ModelState.AddModelError("","A file must be attached");
            }
            else if (!spreadsheet.FileName.EndsWith(".xlsx"))
            {
                ModelState.AddModelError("", "must be an Excel (.xlsx) file");
            }
            if (ModelState.IsValid)
            {
                ViewBag.Updated = await GiveALittleCommunication.AddReceipts(spreadsheet.InputStream);
            }
            return View();
        }
        [Authorize(Roles=Admin)]
        public ActionResult EmailSubscribers()
        {
            return View();
        }

        [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = Admin)]
        public async Task<ActionResult> EmailSubscribers(EmailSubscribersModel model, HttpPostedFileBase attachment)
        {
            if (ModelState.IsValid)
            {
                await SubscriberServices.SendSubscriberEmails(model.Subject, model.Message, attachment);
                return RedirectToAction("Index","Manage");
            }
            return View(model);
        }

        static ReceiptModel GetNewReceiptModel()
        {
            var returnVar = new ReceiptModel();
            //returnVar.Countries = EnumHelpers.AsListItem<Countries>();
            //returnVar.TransferMethods = EnumHelpers.AsListItem<DonationTypes>();
            return returnVar;
        }
    }
}