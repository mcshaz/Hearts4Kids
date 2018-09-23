using Hearts4Kids.Models;
using Hearts4Kids.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Hearts4Kids.Tests.Controllers
{
    [Authorize]
    public class FundraisersControllerTest
    {
        // GET: Fundraisers
        [AllowAnonymous]
        public async Task<ActionResult> Index()
        {
            return View(await FundraisingServices.GetFundraisers());
        }
        public async Task<ActionResult> CreateEdit(int? id)
        {
            FundraisingEventModel model;
            if (id.HasValue)
            {
                model = await FundraisingServices.GetFundraiser(id.Value);
            }
            else
            {
                model = new FundraisingEventModel
                {
                    Organisers = await FundraisingServices.GetMembers()
                };
            }
            return View(model);
        }
        [HttpPost,ValidateAntiForgeryToken]
        public async Task<ActionResult> CreateEdit(FundraisingEventModel model, HttpPostedFileBase flyer)
        {
            if (ModelState.IsValid)
            {
                await FundraisingServices.CreateFundraiser(model, flyer);
                return RedirectToAction("Index");
            }
            model.Organisers = await FundraisingServices.GetMembers();
            return View(model);
        }
    }
}