package iprange;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.googlecode.ipv6.IPv6Address;
import com.googlecode.ipv6.IPv6AddressRange;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.systemwideinterfaces.core.AuthenticationRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.systemwideinterfaces.core.ISession;
import com.mendix.systemwideinterfaces.core.IUser;
import com.mendix.systemwideinterfaces.core.UserAction;

import iprange.proxies.IPAddressRange;
import iprange.proxies.IPType;
import iprange.proxies.SessionIPRange;
import system.proxies.UserRole;

public class IPRangeCheckerLoginAction extends UserAction<ISession>
{

	private String userName;
	private String password;
	private IMxRuntimeRequest request;
	private String currentSessionId;
	public final static String USER_NAME_PARAM = "userName";
	public final static String PASSWORD_PARAM = "password";

	private final static ILogNode _logNode = Core.getLogger("IPCheck");

	public IPRangeCheckerLoginAction( Map<String, ? extends Object> params ) {
		super(Core.createSystemContext());
		this.userName = (String) params.get(USER_NAME_PARAM);
		this.password = (String) params.get(PASSWORD_PARAM);
		this.currentSessionId = (String) params.get("currentSessionId");
		this.request = (IMxRuntimeRequest) params.get("request");
	}


	@Override
	public ISession executeAction() throws Exception
	{
		String remoteAddress = this.request.getRemoteAddr();
		String forwardedFor = this.request.getHeader("X-Forwarded-For");
		String realIP = this.request.getHeader("X-Real-IP"); // This is the header which should be used to check the IP
																// address range.
		_logNode.info("New login request (X-Real-IP: " + realIP + ", X-Forwarded-For:" + forwardedFor + ", remote address: " + remoteAddress);

		if ( realIP == null )
			realIP = forwardedFor;
		if ( realIP == null )
			realIP = remoteAddress;

		IUser user = Core.getUser(getContext(), this.userName);
		if ( user == null )
			throw new AuthenticationRuntimeException("Login FAILED: unknown user '" + this.userName + "'.");
		else if ( user.isWebserviceUser() )
			throw new AuthenticationRuntimeException("Login FAILED: client login attempt for web service user '" + this.userName + "'.");
		else if ( user.isAnonymous() )
			throw new AuthenticationRuntimeException("Login FAILED: client login attempt for guest user '" + this.userName + "'.");
		else if ( user.isActive() == false )
			throw new AuthenticationRuntimeException("Login FAILED: user '" + this.userName + "' is not active.");
		else if ( user.isBlocked() == true )
			throw new AuthenticationRuntimeException("Login FAILED: user '" + this.userName + "' is blocked.");
		else if ( user.getUserRoleNames().isEmpty() )
			throw new AuthenticationRuntimeException("Login FAILED: user '" + this.userName + "' does not have any user roles.");

		IMendixIdentifier matchingIPRange = validIp(Core.createSystemContext(), realIP, user);
		if ( matchingIPRange == null )
			throw new AuthenticationRuntimeException("Login FAILED: user '" + this.userName + "' is not allowed to login from this ip-address(" + realIP + ")");
		else if ( !Core.authenticate(Core.createSystemContext(), user, this.password) )
			throw new AuthenticationRuntimeException("Login FAILED: invalid password for user '" + user.getName() + "'.");


		ISession session = Core.initializeSession(user, this.currentSessionId);
		
		IContext sessionContext = Core.createSystemContext();
		IMendixObject userSessionRange = Core.instantiate(sessionContext, SessionIPRange.entityName);
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.SessionIPRange_IPAddressRange.toString(), matchingIPRange);
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.SessionIPRange_Session.toString(),
				(session.getMendixObject() != null ? session.getMendixObject().getId() : null));
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.SessionIPRange_User.toString(), session.getUserId());
		
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.RemoteAddress.toString(), remoteAddress);
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.XForwardedIP.toString(), forwardedFor);
		userSessionRange.setValue(sessionContext, SessionIPRange.MemberNames.XRealIP.toString(), realIP);
		
		Core.commit(sessionContext, userSessionRange);
		
		return session;
	}

	/**
	 * 
	 * @param context
	 * @param sourceIP
	 * @param user
	 * @return A list of all matching ranges, Returning NULL means no match, If a list is returned that means the user
	 *         is allowed in
	 * @throws CoreException
	 */
	private static IMendixIdentifier validIp( IContext context, String sourceIP, IUser user ) throws CoreException {
		if ( sourceIP != null ) {
			Set<String> userRoleNames = user.getUserRoleNames();
			String xPath = "";
			for( String name : userRoleNames ) {
				if ( !"".equals(xPath) )
					xPath += " or ";
				xPath += "(Name='" + name + "')";
			}

			List<IMendixObject> result = Core
					.retrieveXPathQuery(
							context,
							"//" + IPAddressRange.getType() + "[" + IPAddressRange.MemberNames.IPAddressRange_UserRole + "/" + UserRole.getType() + "[" + xPath + "]]");

			_logNode.trace("Found: " + result.size() + " ranges applicable for user roles: " + xPath + " start looking for match on IP [" + sourceIP + "]"); 

			if ( result.size() > 0 ) {
				String[] ipArr = sourceIP.split("[.]");
				for( IMendixObject obj : result ) {
					String part1 = (String) obj.getValue(context, IPAddressRange.MemberNames.Part1.toString()), part2 = (String) obj.getValue(
							context, IPAddressRange.MemberNames.Part2.toString()), part3 = (String) obj.getValue(context,
							IPAddressRange.MemberNames.Part3.toString());
					String IPV6_start = (String) obj.getValue(context, IPAddressRange.MemberNames.IPV6Address_RangeStart.toString());
					String IPV6_end = (String) obj.getValue(context, IPAddressRange.MemberNames.IPV6Address_RangeEnd.toString());

					boolean allowAllRanges = (Boolean) obj.getValue(context, IPAddressRange.MemberNames.AllRangesAllowed.toString());
					String iptype = (String) obj.getValue(context, IPAddressRange.MemberNames.IPType.toString());

					if ( allowAllRanges ) {
						_logNode.debug("Allowing all IP Ranges for : " + obj.getValue(context, IPAddressRange.MemberNames.Description.toString()) );
						 return obj.getId();
					}
					else if ( IPType.IPV6.toString().equals(iptype) ) {
						IPv6AddressRange range = IPv6AddressRange.fromFirstAndLast(IPv6Address.fromString(IPV6_start), IPv6Address.fromString(IPV6_end));
						if ( range.contains(IPv6Address.fromString(sourceIP)) ) {
							_logNode.debug("MATCHED  [" + sourceIP + "] to IPV6 range: " + IPV6_start + "/" + IPV6_end + " : " + obj.getValue(context, IPAddressRange.MemberNames.Description.toString()) );
							return obj.getId();
						}
						
						_logNode.trace("No Match [" + sourceIP + "] IPV6 range: " + IPV6_start + "/" + IPV6_end + " : " + obj.getValue(context, IPAddressRange.MemberNames.Description.toString()) );
					}

					else if ( IPType.IPV4.toString().equals(iptype) ) {
						Integer startRange = (Integer) obj.getValue(context, IPAddressRange.MemberNames.RangeStart.toString()), endRange = (Integer) obj.getValue(context, IPAddressRange.MemberNames.RangeEnd.toString());
						if ( ipArr[0].equals(part1) && ipArr[1].equals(part2) && ipArr[2].equals(part3) ) {
							int part4 = Integer.valueOf(ipArr[3]);
							if ( part4 >= startRange && part4 <= endRange ) {
								_logNode.debug("MATCHED  [" + sourceIP + "] to IPV4 range: " + part1 + "." + part2 + "." + part3 + " . (" + startRange + "/" + endRange + ") : " + obj.getValue(context, IPAddressRange.MemberNames.Description.toString()) );
								return obj.getId();
							}
						}
						_logNode.trace("No Match [" + sourceIP + "] IPV4 range: " + part1 + "." + part2 + "." + part3 + " . (" + startRange + "/" + endRange + ") : " + obj.getValue(context, IPAddressRange.MemberNames.Description.toString()) );
					}
				}
			}
			else 
				_logNode.error("No IP Rules found for any of the roles " + userRoleNames + ", login not allowed");
		}
		else
			_logNode.error("IP address is empty! Unable to perform check on the rules, login not allowed");

		return null;
	}
	
	public static void setupRulesForAllRoles() throws CoreException {
		IContext context = Core.createSystemContext();
		List<IMendixObject> userRoles = Core.retrieveXPathQuery(context, "//System.UserRole");
		for(IMendixObject role : userRoles ) {
			try {
				String roleName = role.getValue(context, "Name");
				
				if( Core.getConfiguration().getEnableGuestLogin() && roleName.equals(Core.getConfiguration().getGuestUserRoleName()) )
					continue;
				
				long count = Core.retrieveXPathQueryAggregate(context, "count(//" + IPAddressRange.entityName + "[" + IPAddressRange.MemberNames.IPAddressRange_UserRole + " = " + role.getId().toLong() + "])");
				if( count == 0 ) { 
					IMendixObject ipRange = Core.instantiate(context, IPAddressRange.entityName);
					ipRange.setValue(context, IPAddressRange.MemberNames.AllRangesAllowed.toString(), true);
					ipRange.setValue(context, IPAddressRange.MemberNames.Description.toString(), "Auto generated rule for role : " + roleName);
					ArrayList<IMendixIdentifier> roleList = new ArrayList<IMendixIdentifier>();
					roleList.add(role.getId());
					ipRange.setValue(context, IPAddressRange.MemberNames.IPAddressRange_UserRole.toString(), roleList);
					Core.commit(context, ipRange);
					_logNode.info("Creating auto generated rule for role : " + roleName );
				}
			}
			catch (Exception e) {
				_logNode.error("Unable to create IPRange record for: " + role.getValue(context, "Name") + " because of error: " + e.getMessage(), e);
			}
		}
	}
}