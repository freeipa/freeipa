module IPAKrb5 =
  autoload xfm

  let dels (s:string) = Util.del_str s

  let indent    = Util.indent
  let space     = Sep.space
  let opt_space = Sep.opt_space
  let sep       = Sep.space_equal
  let eol       = IniFile.eol

  let kw  = Rx.word
  let val = Rx.space_in

  let comment = IniFile.comment IniFile.comment_re "# "
  let empty   = IniFile.empty

  let entry_generic (v:lens) = [ indent . key kw . sep . v . eol ]

  (*
    FIXME: combine entry and subrecord into a single recursive lens

    This does not work for some reason:
      let rec entry = entry_generic ( store ( val - "{" ) )
                    | entry_generic ( dels "{" . eol
                                    . ( entry | comment | empty )*
                                    . indent . dels "}" )
  *)
  let entry     = entry_generic ( store ( val - "{" ) )
  let subrecord = entry_generic ( dels "{" . eol
                                . ( entry | comment | empty )*
                                . indent . dels "}" )

  let title  = IniFile.indented_title kw
  let record = IniFile.record title ( entry | subrecord | comment )

  let directive = Build.key_value_line kw space ( store val )

  let lns = IniFile.lns record ( directive | comment )

  let filter = incl "/etc/krb5.conf"
             . incl "/etc/krb5.conf.d/*"
             . incl "/var/kerberos/krb5kdc/kdc.conf"
             . Util.stdexcl

  let xfm = transform lns filter
