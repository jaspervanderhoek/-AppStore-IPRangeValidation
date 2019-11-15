package iprange.actions;

import iprange.IPRangeCheckerLoginAction;

import com.mendix.core.Core;
import com.mendix.core.action.user.LoginAction;
import com.mendix.systemwideinterfaces.core.UserActionListener;

public class LoginActionListener extends UserActionListener<LoginAction>
{
	public LoginActionListener()
	{
		super(LoginAction.class);
	}

	@Override
	public boolean check(LoginAction action)
	{
		Core.addUserAction(IPRangeCheckerLoginAction.class);
		return true;
	}
}