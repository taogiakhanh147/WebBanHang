using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WebBanHangOnline.Models;
using WebBanHangOnline.Models.EF;

namespace WebBanHangOnline.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private ApplicationDbContext db = new ApplicationDbContext();

        public AccountController() { }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set { _signInManager = value; }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set { _userManager = value; }
        }

        public ActionResult Index()
        {
            var items = db.Users.ToList();
            return View(items);
        }

        public ActionResult View(string id)
        {
            var user = UserManager.FindById(id);
            var roles = UserManager.GetRoles(id);
            ViewBag.UserRole = roles.Any() ? roles.First() : "";
            return View(user);
        }

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            var model = new LoginViewModel
            {
                ReturnUrl = returnUrl
            };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AdminLogin(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Textbox is empty or invalid format");
                return View("Login",model);
            }

            // Hủy bỏ session hiện tại trước khi đăng nhập mới
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    var user = await UserManager.FindByNameAsync(model.Email);
                    var identity = await user.GenerateUserIdentityAsync(UserManager, DefaultAuthenticationTypes.ApplicationCookie);
                    AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = model.RememberMe }, identity);

                    if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return RedirectToAction("Index", "Home", new { area = "Admin" });
                    }
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View("Login", model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Login", "Account", new { area = "Admin" });
        }

        private IAuthenticationManager AuthenticationManager
        {
            get { return HttpContext.GetOwinContext().Authentication; }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        public async Task<ActionResult> Edit(string id)
        {
            var user = await UserManager.FindByIdAsync(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            var roles = db.Roles.ToList();
            ViewBag.Role = new SelectList(roles, "Name", "Name");

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(ApplicationUser user, string password, string confirmPassword, string role)
        {
            if (ModelState.IsValid)
            {
                var currentUser = await UserManager.FindByIdAsync(user.Id);
                if (currentUser == null)
                {
                    return HttpNotFound();
                }

                // Cập nhật thông tin người dùng
                currentUser.UserName = user.UserName;
                currentUser.CustomerName = user.CustomerName;
                currentUser.Email = user.Email;
                currentUser.CustomerPhone = user.CustomerPhone;
                currentUser.CustomerAddress = user.CustomerAddress;

                // Cập nhật mật khẩu nếu được cung cấp
                if (!string.IsNullOrEmpty(password))
                {
                    if (password == confirmPassword)
                    {
                        currentUser.PasswordHash = UserManager.PasswordHasher.HashPassword(password);
                    }
                    else
                    {
                        ModelState.AddModelError("", "Mật khẩu và Nhập lại Mật khẩu không khớp.");
                        ViewBag.Role = new SelectList(db.Roles.ToList(), "Name", "Name", role);
                        return View(user);
                    }
                }

                // Cập nhật vai trò
                var currentRoles = await UserManager.GetRolesAsync(currentUser.Id);
                if (!string.IsNullOrEmpty(role) && !currentRoles.Contains(role))
                {
                    await UserManager.RemoveFromRolesAsync(currentUser.Id, currentRoles.ToArray());
                    await UserManager.AddToRoleAsync(currentUser.Id, role);
                }

                var result = await UserManager.UpdateAsync(currentUser);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                AddErrors(result);
            }

            // Nếu có lỗi, lấy lại danh sách quyền để hiển thị trong dropdown
            ViewBag.Role = new SelectList(db.Roles.ToList(), "Name", "Name");
            return View(user);
        }

        [HttpPost]
        public ActionResult Delete(string id)
        {
            var item = db.Users.Find(id);
            if (item != null)
            {
                db.Users.Remove(item);
                db.SaveChanges();
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }
    }
}
