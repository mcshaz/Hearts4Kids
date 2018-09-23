using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Hearts4Kids.Models;
using System.Threading.Tasks;
using System.Net.Mail;
using System.Collections.Generic;
using System.Linq;
using System.Data.Entity;

namespace Hearts4Kids.Controllers
{
    public abstract class BaseUserController : Controller
    {
        private ApplicationUserManager _userManager;
        private ApplicationRoleManager _roleManager;
        private ApplicationUser _currentUser;
        private ApplicationSignInManager _signInManager;
        bool? _isAdmin;

        public BaseUserController()
        {
        }

        public BaseUserController(ApplicationUserManager userManager, ApplicationRoleManager roleManager,ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            RoleManager = roleManager;
            AppSignInManager = signInManager;
        }
        // GET: BaseUser
        internal static ApplicationUserManager GetApplicationUserManager()
        {
            return System.Web.HttpContext.Current.GetOwinContext().Get<ApplicationUserManager>();
        }


        protected ApplicationSignInManager AppSignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }
        protected ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? GetApplicationUserManager();
            }
            private set
            {
                _userManager = value;
            }
        }
        internal static ApplicationRoleManager GetApplicationRoleManager()
        {
            return System.Web.HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();
        }
        protected ApplicationRoleManager RoleManager
        {
            get
            {
                return _roleManager ?? GetApplicationRoleManager();
            }
            private set
            {
                _roleManager = value;
            }
        }
        protected async Task<ApplicationUser> GetCurrentUserAsync()
        {
            var usr = await UserManager.FindByNameAsync(User.Identity.Name);
            return usr;
        }
        protected ApplicationUser CurrentUser
        {
            get
            {
                if (_currentUser == null)
                {
                    string name = User.Identity.Name;
                    _currentUser = UserManager.FindByName(name);
                }
                return _currentUser;
            }
        }
        protected async Task<bool> IsAdminAsync()
        {
            if (_currentUser == null)
            {
                string name = User.Identity.Name;
                _currentUser = await UserManager.FindByNameAsync(name);
            }
            _isAdmin = await UserManager.IsInRoleAsync(_currentUser.Id, Domain.DomainConstants.Admin);
            return _isAdmin.Value;
        }
        protected bool IsAdmin
        {
            get
            {
                return _isAdmin ?? (_isAdmin = UserManager.IsInRole(CurrentUser.Id, Domain.DomainConstants.Admin)).Value;
            }
        }
        #region email
        public async Task SendToUserAsync(ApplicationUser usr , string subject, string body)
        {
            var client = new SmtpClient();
            client.SendCompleted += (s, e) => {
                client.Dispose();
            };
            var mail = new MailMessage { Subject = subject, Body = body, IsBodyHtml = true };
            mail.To.Add(usr.Email);
            await client.SendMailAsync(mail);
        }
        public async Task SendEmailsToRoleAsync(string roleName, IdentityMessage message)
        {
            var client = new SmtpClient();
            client.SendCompleted += (s, e) => {
                client.Dispose();
            };
            var mail = new MailMessage { Subject = message.Subject, Body = message.Body, IsBodyHtml = true };
            var admins = await GetEmailsInRole(roleName);
            foreach (var to in admins)
            {
                mail.To.Add(to);
            }
            await client.SendMailAsync(mail); //not awaiting, as calling code can do that
        }
        public async Task<List<string>> GetEmailsInRole(string roleName)
        {
            return await (from u in await GetUsersInRole(roleName)
                            select u.Email).ToListAsync();
        }
        public async Task<IQueryable<ApplicationUser>> GetUsersInRole(string roleName)
        {
            var roleId = (await RoleManager.FindByNameAsync(roleName)).Id;
            return UserManager.Users.Where(u => u.Roles.Any(r=>r.RoleId == roleId));
        }
        #endregion

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_roleManager != null)
                {
                    _roleManager.Dispose();
                    _roleManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }
    }
}