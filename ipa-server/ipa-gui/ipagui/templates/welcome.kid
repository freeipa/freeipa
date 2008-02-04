<!-- 
 Copyright (C) 2007  Red Hat
 see file 'COPYING' for use and warranty information

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 only

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
-->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Welcome</title>
</head>
<body>
    <div id="details">
        <div id="alertbox" py:if="value_of('tg_flash', None)">
            <p py:content="XML(tg_flash)"></p></div>
        <h1>Welcome to Free IPA</h1>

        <noscript>
        <span class="warning_message">
        This site makes heavy use of JavaScript.<br />
        Please enable JavaScript in your browser to make sure all pages function properly.
        </span>
        </noscript>

        <p>
IPA is used to manage Identity, Policy, and Auditing for your organization.
        </p>
        <p>
          To get started, you can use the search box in the top right to find
          users or groups you need to work on.  Search automatically looks
          across multiple fields.  If you want to find Joe in Finance, try typing
          "joe finance" into the search box.
        </p>
        <p>
          Alternatively, select a task from the right sidebar.
        </p>
    </div>

</body>
</html>
