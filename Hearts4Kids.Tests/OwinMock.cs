using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;

namespace Hearts4Kids.Tests
{
    public static class OwinMock
    {
        //https://stackoverflow.com/questions/24836845/request-getowincontext-returns-null-within-unit-test-how-do-i-test-owin-authen
        public static HttpRequest CreateMockContext()
        {
            var request = new HttpRequest("", "http://google.com", "rUrl=http://www.google.com")
            {
                ContentEncoding = Encoding.UTF8  //UrlDecode needs this to be set
            };

            var ctx = new HttpContext(request, new HttpResponse(new StringWriter()));

            //Session need to be set
            var sessionContainer = new HttpSessionStateContainer("id", new SessionStateItemCollection(),
                new HttpStaticObjectsCollection(), 10, true,
                HttpCookieMode.AutoDetect,
                SessionStateMode.InProc, false);
            //this adds aspnet session
            ctx.Items["AspSession"] = typeof(HttpSessionState).GetConstructor(
                BindingFlags.NonPublic | BindingFlags.Instance,
                null, CallingConventions.Standard,
                new[] { typeof(HttpSessionStateContainer) },
                null)
                .Invoke(new object[] { sessionContainer });

            var data = new Dictionary<string, object>()
            {
                {"a", "b"} // fake whatever  you need here.
            };

            ctx.Items["owin.Environment"] = data;
            return request;
        }
    }
}
