using Casbin.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApplicationSample.Controllers
{
    [ApiController]
    [Route("/api")]
    public class ApiController : Controller
    {

        [HttpGet("index")]
        [CasbinAuthorize]
        public IActionResult Index()
        {
            return new JsonResult(new
            {
                Message = "You passed the casbin authorize."
            });
        }


        [HttpGet("{tenantid}/company/add")]
        [CasbinAuthorize]
        public IActionResult AddCustomerToTenant(string tenantid, [FromQuery]string addRequest)
        {
            return new JsonResult(new
            {
                Message = $"tenantid = {tenantid}, request = {addRequest}"
            });
        }
    }
}
