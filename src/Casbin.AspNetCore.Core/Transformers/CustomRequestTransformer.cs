using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Routing;

namespace Casbin.AspNetCore.Authorization.Transformers
{
    public class CustomRequestTransformer : IRequestTransformer
    {
        public string? Issuer { get; set; }
        public string? PreferSubClaimType { get; set; } = ClaimTypes.NameIdentifier;

        public virtual ValueTask<IEnumerable<object>> TransformAsync(ICasbinAuthorizationContext context, ICasbinAuthorizationData data)
        {
            var requestValues = new object[4];
            requestValues[0] = SubTransform(context, data);
            requestValues[1] = DomTransform(context, data);
            requestValues[2] = ObjTransform(context, data);
            requestValues[3] = ActTransform(context, data);
            return new ValueTask<IEnumerable<object>>(requestValues);
        }

        public virtual string SubTransform(ICasbinAuthorizationContext context, ICasbinAuthorizationData data)
        {
            Claim? claim;
            if (Issuer is null)
            {
                claim = context.User.FindFirst(PreferSubClaimType);
                return claim is null ? string.Empty : claim.Value;
            }

            claim = context.User.FindAll(PreferSubClaimType).FirstOrDefault(
                c => string.Equals(c.Issuer, Issuer));
            return claim is null ? string.Empty : claim.Value;
        }
        public virtual string DomTransform(ICasbinAuthorizationContext context, ICasbinAuthorizationData data)
        {
            var request = context?.Request ;
            if (request == null)
            {
                throw new Exception("Missing HttpRequest in CasbinAuthorizationContext");
            }

            var routeData = request.HttpContext.GetRouteData();
            var tenantItem = routeData.Values.SingleOrDefault(kv => kv.Key.ToLowerInvariant() == "tenantid");
            string? tenantId = tenantItem.Key != null ? tenantItem.Value.ToString().ToLowerInvariant() : null;
            return data.Value1 ?? tenantId?.ToLowerInvariant() ?? "__NO_TENANTID__";
        }
        public virtual string ObjTransform(ICasbinAuthorizationContext context, ICasbinAuthorizationData data)
        {
            var request = context?.Request;
            if (request == null)
            {
                throw new Exception("Missing HttpRequest in CasbinAuthorizationContext");
            }
            return data.Value1 ?? request.Path.Value?.ToLowerInvariant() ?? string.Empty;
        }

        public virtual string ActTransform(ICasbinAuthorizationContext context, ICasbinAuthorizationData data)
        {
            var request = context?.Request;
            if (request == null)
            {
                throw new Exception("Missing HttpRequest in CasbinAuthorizationContext");
            }
            return data.Value2 ?? request.Method ?? string.Empty;
        }
    }
}
