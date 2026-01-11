from __future__ import annotations

import win32com.client


class OutlookError(RuntimeError):
    pass


def send_email(subject: str, body: str, recipients: list[str], attachments: list[str]) -> str:
    try:
        if not recipients:
            raise OutlookError("No recipients supplied.")
        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
        except Exception as exc:
            args = getattr(exc, "args", ())
            if args and args[0] == -2147221005:
                raise OutlookError(
                    "Outlook is not available. Ensure Outlook is installed and configured for the "
                    "current Windows session."
                ) from exc
            raise
        mail = outlook.CreateItem(0)
        mail.Subject = subject
        mail.Body = body
        for recipient in recipients:
            mail.Recipients.Add(recipient)
        if not mail.Recipients.ResolveAll():
            raise OutlookError("Unable to resolve one or more recipients.")
        for attachment in attachments:
            mail.Attachments.Add(attachment)
        mail.Send()
        try:
            return mail.EntryID
        except Exception:
            return ""
    except Exception as exc:
        raise OutlookError(str(exc)) from exc
