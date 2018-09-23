using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Hearts4Kids.Models;
using System;
using Hearts4Kids.Services;
using System.Collections.Generic;

namespace Hearts4Kids.Controllers
{
    [Authorize]
    public class AccountController : BaseUserController
    {
        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager, ApplicationRoleManager roleManager, IAuthenticationManager authManager)
                : base(userManager, roleManager, signInManager)
        {
            _authManager = authManager;
        }


        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
#if DEBUG
            await RegisterAdmin();
#endif
            //var usr = UserManager.FindByName(model.UserName);
            SignInStatus result;

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            result = await AppSignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, shouldLockout: true);

            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification: //this is fr verification on every login
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt. If you have been sent an email to join, please click the email link to join.");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await AppSignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await AppSignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }
        [HttpPost]
        public async Task<ActionResult> DeleteUser(int id)
        { 
            if (id==User.Identity.GetUserId<int>()){
                throw new UnauthorizedAccessException();
            }
            var usr = await UserManager.FindByIdAsync(id);
            await UserManager.DeleteAsync(usr);
            await SendToUserAsync(usr, "Heart4Kids Account", "This account has been deleted. Usually this will be because another email has been associated "
                +"with you. If this is a mistake, please let Brent know.");
            return new JsonResult { Data = new { success = true } };
        }
        [Authorize(Roles = Domain.DomainConstants.Admin)]
        public ActionResult CreateUsers()
        {
            return View();
        }
        public const string bioInstructions = "<blockquote>"
                                + " <p>We would love you to create a bio for the team page of a paragraph or few sentences.</p>"
                                + "<p>Please write it in the third person.<p>"
                                + "<p>You may want to include.</p>"
                                + "<ul><li>your role</li>"
                                + "<li>past experience</li>"
                                + "<li><strong>comment on last year / what you hope to get from this year. (<q>a quote</q>)</strong></li>"
                                + "<li>something else about you.</li>"
                                + "<li>Hope that this is not too prescriptive, but then they all match.</li></ul>"
                                + "<p>Thank you,</p><p> <em>Kate Farmer</em> (on behalf of all the H4K team)</p>"
                                + "</blockquote>";
        [Authorize(Roles = Domain.DomainConstants.Admin), HttpPost, ValidateAntiForgeryToken]
        public async Task<ActionResult> CreateUsers(CreateUsersViewModel model)
        {
            if (ModelState.IsValid)
            {
                var emailVal = new System.ComponentModel.DataAnnotations.EmailAddressAttribute();
                var errorMails = new List<string>();
                foreach (var em in (model.EmailList ?? string.Empty).Split(new char[] { ';', ',','\r','\n',' ','<','>' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (emailVal.IsValid(em))
                    {
                        var user = new ApplicationUser { UserName = em, Email = em, EmailConfirmed=false };
                        var result = await UserManager.CreateAsync(user);
                        if (result.Succeeded)
                        {
                            if (model.MakeAdministrator)
                            {
                                result = await UserManager.AddToRoleAsync(user.Id, Domain.DomainConstants.Admin);
                            }
                            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                            // Send an email with this link
                            await SendInviteAsync(user.Id);

                        }
                        else
                        {
                            errorMails.Add(em);
                            AddErrors(result);
                        }
                        
                    }
                    else
                    {
                        ModelState.AddModelError("", "Invalid email:" + em);
                        errorMails.Add(em);
                    }
                }
                if (ModelState.IsValid)
                {
                    return RedirectToAction("Index", "Manage", new { message = ManageController.ManageMessageId.UsersAdded });
                }
                model.EmailList = string.Join("r\n", errorMails);
            }
            
            return View(model);

        }
        public const int TokenExpireDays = 30;
        private async Task SendInviteAsync(int userId)
        {
            string code = await UserManager.GenerateEmailConfirmationTokenAsync(userId);

            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId, code }, protocol: Request.Url.Scheme);
            await UserManager.SendEmailAsync(userId, "Finalise your Hearts4Kids account", "<h2>Welcome to Hearts4Kids.</h2>"
                + "<p>Please set up your account by clicking <a href=\"" + callbackUrl + "\">here</a></p>"
                + "<p>Because we believe the professionals (like you) volunteering their time are the selling point for our charity, "
                + "we would appreciate some info from you to finalise setting up your account.</p>"
                + "<p>After clicking the link, you will be asked to provide some details "
                + "(which like this email address will only be available to team members), after which you will be taken to a page "
                + "where you will be asked to provide a short biography and picture to go up on our website for public viewing, as described below:</p>"
                + "<hr/>"
                + bioInstructions);
        }
        //optional param in case they come back later
        //
        // GET: /Account/Register
        public ActionResult Register()
        {
            if (!string.IsNullOrEmpty(CurrentUser.PasswordHash))
            {
                return RedirectToAction("UpdateDetails", "Bios");
            }
            var model = new RegisterDetailsViewModel
            {
                Email = CurrentUser.Email,
                UserName = CurrentUser.UserName,
                UserId = CurrentUser.Id
            };
            return View(model);
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterDetailsViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.UserId != CurrentUser.Id)
                {
                    throw new System.Security.SecurityException();
                }
                bool newUserName = CurrentUser.UserName != model.UserName;
                CurrentUser.UserName = model.UserName;
                CurrentUser.PhoneNumber = model.PhoneNumber;
                var result = await UserManager.UpdateAsync(CurrentUser);
                if (result.Succeeded)
                {
                    if (newUserName)
                    {
                        AuthenticationManager.SignOut();
                        await AppSignInManager.SignInAsync(CurrentUser, isPersistent: false, rememberBrowser: false);
                    }
                    result = await UserManager.AddPasswordAsync(CurrentUser.Id, model.Password);
                    if (result.Succeeded)
                    {
                        MemberDetailServices.UpdateMemberDetails(model, ModelState);
                        if (ModelState.IsValid)
                        {
                            return RedirectToAction("CreateEditBio", "Bios");
                        }
                    }
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        public ActionResult EmailResent()
        {
            return View();
        }
        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(int userId, string code)
        {
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
                await AppSignInManager.SignInAsync(usr, isPersistent: false, rememberBrowser: false);
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
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code }, protocol: Request.Url.Scheme);
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
            var userId = await AppSignInManager.GetVerifiedUserIdAsync();
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
            if (!await AppSignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, model.ReturnUrl, model.RememberMe });
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

        async Task RegisterAdmin()
        {
            ApplicationUser user = null;
            if (!UserManager.Users.Any())
            {
                user = new Models.ApplicationUser
                {
                    UserName = "brentm",
                    Email = "brent@focused-light.net",
                    PhoneNumber = "021 245 9769",
                    PhoneNumberConfirmed = true,
                    EmailConfirmed = true
                };
                var result = await UserManager.CreateAsync(user, "Abcd.1");
                CheckResult(result, "Register User");
            }

            if (!RoleManager.RoleExists(Domain.DomainConstants.Admin))
            {
                if (user == null) { user = UserManager.FindByName("brentm"); }
                System.Diagnostics.Debug.Assert(user.Id != 0, "userId not assigned");

                ApplicationRole role = new ApplicationRole { Name = Domain.DomainConstants.Admin };
                var result = await RoleManager.CreateAsync(role);
                CheckResult(result, "Create Role");
                result = await UserManager.AddToRoleAsync(user.Id, Domain.DomainConstants.Admin);
                CheckResult(result, "Assign Role To User");
            }
        }
        static void CheckResult(IdentityResult result, string taskDescription)
        {
            if (!result.Succeeded)
            {
                var ex = new Exception(string.Format("Unable to {0}.", taskDescription));
                ex.Data.Add("CreateErrors", string.Join(";\r\n", result.Errors));
                throw ex;
            }
        }

#region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        IAuthenticationManager _authManager;
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return _authManager ?? (_authManager = HttpContext.GetOwinContext().Authentication);
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
#endregion
    }
}