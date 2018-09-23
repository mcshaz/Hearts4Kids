using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Hearts4Kids.Models;
using System;
using Hearts4Kids.Services;
using System.Collections.Generic;
using Hearts4Kids.Controllers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net.Http;
using Moq;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Security.Principal;
using System.Web.Routing;
using Microsoft.Owin.Security;

namespace Hearts4Kids.Tests.Controllers
{
    [TestClass]
    public class AccountControllerTest
    {
        //
        // GET: /Account/Login
        [TestMethod]
        public void LoginGet()
        {

            var controller = new AccountController();

            ViewResult result = controller.Login("/") as ViewResult;

            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async void LoginPost()
        {
            var controller = new AccountController();

            var lvm = new LoginViewModel
            {
                Password = "x",
                UserName = "y"
            };
            var result = await controller.Login(lvm, "/");
            Assert.IsNotNull(result);
            Assert.IsInstanceOfType(result, typeof(RedirectResult));

        }

        private static ApplicationUser GetTestUser()
        {
            return new ApplicationUser
            {
                UserName = "test",
                Email = "test@example.com",
                PhoneNumber = "999 9999 999",
                PhoneNumberConfirmed = true,
                EmailConfirmed = true
            };
        }
        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async void Login(LoginViewModel model, string returnUrl)
        {
            //2.2.1 - 2.2.2 
            
            var um = new Mock<ApplicationUserManager> { DefaultValue = DefaultValue.Mock } ;
            /*
            um.Setup(m => m.FindByName(un)).Returns(() => new ApplicationUser
            {
                UserName = un, 
            });
            */
            var usr = GetTestUser();

            var lvm = new LoginViewModel { UserName = usr.UserName, Password = "abcd.123" };

            um.Setup(m => m.Users).Returns(() => (new[] { usr }).AsQueryable());

            var sm = new Mock<ApplicationSignInManager> { DefaultValue = DefaultValue.Mock };
            sm.SetupSequence(m => m.PasswordSignInAsync(lvm.UserName, lvm.Password, lvm.RememberMe, It.IsAny<bool>()))
                .ReturnsAsync(SignInStatus.Success)
                .ReturnsAsync(SignInStatus.Failure)
                .ReturnsAsync(SignInStatus.LockedOut)
                .ReturnsAsync(SignInStatus.RequiresVerification);

            var controller = new AccountController(um.Object, sm.Object, null,null);

            var result = await controller.Login(lvm, "/");

            //success
            Assert.AreEqual(0, controller.ModelState.Count);
            Assert.IsInstanceOfType(result, typeof(RedirectToRouteResult));
            //var redir = (RedirectToRouteResult)result;

            result = await controller.Login(lvm, "/");

            //failure
            Assert.AreEqual(0, controller.ModelState.Count);
            Assert.IsInstanceOfType(result, typeof(RedirectToRouteResult));
            //requires verification, redirect to action

            result = await controller.Login(lvm, "/");

            //lockout
            Assert.AreEqual(0, controller.ModelState.Count);
            Assert.IsNotNull(result);

            result = await controller.Login(lvm, "/");

            //requires verification
            Assert.AreEqual(0, controller.ModelState.Count);
            Assert.IsNotNull(result);

        }

        [TestMethod]
        public async void VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            var sm = new Mock<ApplicationSignInManager> { DefaultValue = DefaultValue.Mock };
            sm.SetupSequence(m => m.HasBeenVerifiedAsync())
                .ReturnsAsync(false)
                .ReturnsAsync(true);

            var controller = new AccountController(null, sm.Object, null, null);

            for (int i = 0; i < 2; i++)
            {
                var result = await controller.VerifyCode("google.com", "/", false);
                Assert.IsNotNull(result);
            }
        }

        //
        // POST: /Account/VerifyCode
        [TestMethod]
        public async void VerifyCode()
        {
            VerifyCodeViewModel model = new VerifyCodeViewModel
            {
                Code = "abcd",
                Provider = "google.com",
                ReturnUrl = "/"
            };
            var sm = new Mock<ApplicationSignInManager> { DefaultValue = DefaultValue.Mock };
            sm.SetupSequence(m=>m.TwoFactorSignInAsync(model.Provider, model.Code,model.RememberMe, model.RememberBrowser))
                .ReturnsAsync(SignInStatus.Success)
                .ReturnsAsync(SignInStatus.Failure)
                .ReturnsAsync(SignInStatus.LockedOut)
                .ReturnsAsync(SignInStatus.RequiresVerification);
            var controller = new AccountController(null, sm.Object, null,null);
            for (int i = 0; i < 4; i++)
            {
                var result = await controller.VerifyCode(model);
                Assert.IsNotNull(result);
            }

        }
        /*
        [HttpPost]
        public async void DeleteUser(int id)
        {
            var controller = new AccountController(null, sm.Object, null);
            if (id==User.Identity.GetUserId<int>()){
                throw new UnauthorizedAccessException();
            }
            var usr = await UserManager.FindByIdAsync(id);
            await UserManager.DeleteAsync(usr);
            await SendToUserAsync(usr, "Heart4Kids Account", "This account has been deleted. Usually this will be because another email has been associated "
                +"with you. If this is a mistake, please let Brent know.");
            return new JsonResult { Data = new { success = true } };
        }
        */
        [TestMethod]
        public void CreateUsersGet()
        {
            var controller = new AccountController();
            var result = controller.CreateUsers();
            // Assert
            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async void CreateUsersPost()
        {
            var um = new Mock<ApplicationUserManager>();
            const int fakeid = -1234;
            um.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>()))
                .Callback<ApplicationUser>(au=>au.Id = fakeid)
                .ReturnsAsync(IdentityResult.Success);
            um.Setup(m => m.AddToRoleAsync(fakeid, Domain.DomainConstants.Admin))
                .ReturnsAsync(IdentityResult.Success);
            um.Setup(m => m.SendEmailAsync(fakeid, It.IsAny<string>(), It.IsAny<string>()));

            var controller = new AccountController(um.Object,null,null,null);
            var result = await controller.CreateUsers(new CreateUsersViewModel
            {
                EmailList = "john@example.com;mary@errortest",
                MakeAdministrator = false
            });

            um.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>()), Times.Exactly(1));
            um.Verify(m => m.AddToRoleAsync(It.IsAny<int>(), Domain.DomainConstants.Admin), Times.Exactly(1));
            um.Verify(m => m.SendEmailAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string>()), Times.Exactly(1));

            Assert.IsNotNull(result);
            Assert.AreEqual(1, controller.ModelState.Count);
        }

        //optional param in case they come back later
        //
        // GET: /Account/Register
        private class TestIdentity : IIdentity
        {
            public string Name {get; set;}
            public string AuthenticationType { get { return "TestFramework"; } }
            public bool IsAuthenticated { get; set; }
        }

        public async void Register()
        {
            var usr = GetTestUser();
            IIdentity identity = new TestIdentity { Name = usr.UserName, IsAuthenticated = true };
            var principal = new Mock<IPrincipal>();
            // ... mock IPrincipal as you wish
            principal.Setup(m => m.Identity).Returns(identity);
            var httpContext = new Mock<HttpContextBase>();
            httpContext.Setup(x => x.User).Returns(principal.Object);

            var um = new Mock<ApplicationUserManager>();
            um.Setup(m => m.FindByName(identity.Name))
                .Returns(usr);

            var authm = new Mock<IAuthenticationManager>();
            var apm = new Mock<ApplicationSignInManager>();

            var reqContext = new RequestContext(httpContext.Object, new RouteData());
            var ctrlr = new AccountController(um.Object,apm.Object,null,authm.Object);
            
            ctrlr.ControllerContext = new ControllerContext(reqContext, ctrlr);

            var result = ctrlr.Register() as ViewResult;
            Assert.IsNotNull(result);
            Assert.IsInstanceOfType(result, typeof(RedirectToRouteResult));

            usr.PasswordHash = "abcd";

            result = ctrlr.Register() as ViewResult;
            Assert.IsNotNull(result);
            Assert.IsNotInstanceOfType(result, typeof(RedirectToRouteResult));

            var usrModel = new RegisterDetailsViewModel()
            {
                UserId = 1234, UserName = "abc", PhoneNumber="1293", Password="Qwerty!1"
            };
            usr.Id = 5678;

            MyAssert.Throws<System.Security.SecurityException>(async () => await ctrlr.Register(usrModel));

            usrModel.UserId = usr.Id;
            um.SetupSequence(m=>m.UpdateAsync(usr))
                .ReturnsAsync(IdentityResult.Failed("testingfail"))
                .ReturnsAsync(IdentityResult.Success);

            result = await ctrlr.Register(usrModel) as ViewResult;

            Assert.IsNotNull(result);
            var sim = new Mock<ApplicationSignInManager>();

            result = await ctrlr.Register(usrModel) as ViewResult;
            Assert.IsNotNull(result);
            Assert.Equals(usr.UserName, usrModel.UserName);
            Assert.Equals(usr.PhoneNumber, usrModel.PhoneNumber);
            um.Verify(m => m.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Exactly(1));
            
            //username was different, so sign out and sign in
            authm.Verify(m => m.SignOut(), Times.Exactly(1));
            apm.Verify(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, false),Times.Exactly(1));
            um.Verify(m=>m.AddPasswordAsync(usrModel.UserId, usrModel.Password),Times.Exactly(1));
            um.Verify(m => m.AddPasswordAsync(It.IsAny<int>(), It.IsAny<string>()), Times.Exactly(1));
        }

        [TestMethod]
        public void EmailResent()
        {
            var controller = new AccountController();
            var result = controller.EmailResent() as ViewResult;
            Assert.IsNotNull(result);
        }
        //
        // GET: /Account/ConfirmEmail
        [TestMethod]
        public async void ConfirmEmail()
        {
            var controller = new AccountController();

            ConfirmEmail(int userId, string code)
            if (userId == default(int) || code == null)
            {
                return View("Error");
            }
            if (User.Identity.IsAuthenticated) {
                var currentUsr = await UserManager.FindByNameAsync(User.Identity.Name);
                if (currentUsr.Id != userId) {
                    AuthenticationManager.SignOut();
                }
                else if (currentUsr.PasswordHash==null)
                {
                    return RedirectToAction("Register");
                }
                else if (MemberDetailServices.BioRequired(currentUsr.Id))
                {
                    return RedirectToAction("CreateEditBio","Bios");
                }
                else
                {
                    return RedirectToAction("Index", "Manage");
                }
            }

            var usr = await UserManager.FindByIdAsync(userId);
            if (usr == null)
            {
                return View("EmailResent");
            }

            if (usr.EmailConfirmed) {
                return RedirectToAction("Login");
            }
            var provider = (DataProtectorTokenProvider<ApplicationUser, int>)UserManager.UserTokenProvider;
            TimeSpan defaultSpan = provider.TokenLifespan;
            provider.TokenLifespan = TimeSpan.FromDays(TokenExpireDays);
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            provider.TokenLifespan = defaultSpan;

            if (result.Succeeded) {
                await SignInManager.SignInAsync(usr, isPersistent: false, rememberBrowser: false);
                return RedirectToAction("Register");
            }
            await SendInviteAsync(userId);
            return View("EmailResent");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null)
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }
                if (!user.EmailConfirmed || string.IsNullOrEmpty(user.PasswordHash))
                {
                    await SendInviteAsync(user.Id);
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == default(int))
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        /*
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser {UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }
        */
        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }
    }
}