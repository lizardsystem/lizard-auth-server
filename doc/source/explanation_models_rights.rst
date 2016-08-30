Models and rights
=================

The SSO has three main models:

.. glossary::

  user profile
    Basically users that log in. Users can belong to one
    company only. The managers of the company they're a member of can edit their
    account.

  company
    Basically a "group of user profiles". It has one or more
    managers that are allowed to add/edit/remove user profiles as members. User
    profiles that are already a member elsewhere can be made guest members.

    Note that the name "company" and the functionality is aimed at officially
    managing user profiles. This is a consious departure from the old
    "organisation" functionality which was an unmanageable combination of
    "membership" and "data access", so: :term:`authorization`. Which we don't want in
    the new SSO.

  site
    A site that's using the SSO. Currently you need admin access to
    add one. A site can be made available to companies, which means that those
    companies' users can log in on the site.


Central to the SSO's design is correct permissions. A user has no right to
make itself a member of a company, that right has to flow the other way. A
website maintainer has no business adding users to a company, just like a
company has no business granting itself access to a website.

Current permission structure:

- To add a site, you need admin access and the add/edit/delete site
  permissions. This'll be only for our own employees.

- As a regular user, you cannot change anything. *In the future* you'll be
  able to register yourself and change your password and ask a company
  maintainer to add you to their company.

- Editing a company to change the name or add/remove administrators: admin
  access by our own employees, again.

- As a company administrator, you can search for all users because you need to
  be able to add them as member or guest. *Search*, not list, as listing them
  all is a security risk. See how github does it, as an example.

  TODO: check if this works OK in the admin now.

  Users can only be a member of one company. If a user has to be moved to a
  different company, you can either remove the user or choose to convert the
  membership to guest membership. The other company can then add the user as
  member afterwards.
