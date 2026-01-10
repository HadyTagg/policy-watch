from __future__ import annotations

import win32com.client


class OutlookError(RuntimeError):
    pass


def send_email(subject: str, body: str, recipients: list[str], attachments: list[str]) -> str:
    try:
        outlook = win32com.client.Dispatch("Outlook.Application")
        mail = outlook.CreateItem(0)
        mail.Subject = subject
        mail.Body = body
        for recipient in recipients:
            mail.Recipients.Add(recipient)
        for attachment in attachments:
            mail.Attachments.Add(attachment)
        mail.Send()
        try:
            return mail.EntryID
        except Exception:
            return ""
    except Exception as exc:
        raise OutlookError(str(exc)) from exc
