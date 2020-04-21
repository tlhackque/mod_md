/* -*- mode: java; -*-
 * Copyright (C) 2020 Timothe Litt.  Apache licensed, see source.
 */
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

jQuery(function($) {
       $.fn.serializeObject = function(name,data) {
           var o = {};
           var a = this.serializeArray();
           if( name ) {
               a.push( { name: name, value: data } );
           }
           $.each(a, function() {
                      if (o[this.name]) {
                          if (!o[this.name].push) {
                              o[this.name] = [o[this.name]];
                          }
                          o[this.name].push(this.value || '');
                      } else {
                          o[this.name] = this.value || '';
                      }
                  });
           return o;
       };
       Math.trunc = Math.trunc || function(x) { /* IE */
           if( isNaN( x ) ) {
               return NaN;
           }
           if( x > 0 ) {
               return Math.floor( x );
           }
           return Math.ceil( x );
       };
       var
       ajaxTimeout = 75*1000,
       meta  = {},
       kmeta = { termsOfService: "Terms of Service",
                        website: "Website",
                  caaIdentities: "Identities used in DNS CAA records",
        externalAccountRequired: "New account requests must be associated with an external account"
       },
       dposition = { my: "top", at: "top+25", of: window },
       accounts  = {},
       can       = 0,
       domain    = null,
       filter    = null,
       xstatus   = function( xhr, status, what ) {
           if( status == "error" ) {
               status = xhr.status.toString() + " " + xhr.statusText;
           }
           return "<span class='status loaderror'>" + what + " failed: "
           + status + "</span>";
       },
       displayMessageJSON = function( rsp ) {
           if( rsp.hasOwnProperty("message") ) {
               displayMessageText( rsp.message );
           }
           return true;
       },
       displayMessageText = function( txt ) {
           $("#messages").append( "<p>" + txt );
           $(".messages").removeClass( "hidden" );
           return true;
       },
       makebuttons = function(list) {
           list.forEach(function( b, idx ) {
                var sel = b.name.map(function(v,i,a){ return "button[name=\"" + v + "\"]";})
                    .join(",");
                $(sel)
                    .button({
                            icon: b.icon
                                })
                    .on( "click", function(event) {
                             return postCommand(this);
                         });
                        });
       },
       postCommand = function(btn) {
           var form     = $(btn).closest("form");
           $(form).find("input[name=\"function\"]").val(btn.name);
           var first    = $("table.actions tr.pagenav li.active a").attr("value");
           var pagesize = parseInt( $("select[name=\"pagelimit\"]").val() );
           first        = (Math.trunc((first -1) / pagesize) * pagesize) +1;
           var pg = {
               start: parseInt(first),
               count: pagesize };

           $.ajax( window.location.pathname, {
                   contentType: "application/json",
                          data: JSON.stringify($(form).serializeObject("paging", pg)),
                       context: $(form),
                      dataType: "json",
                        method: "POST",
                       timeout: ajaxTimeout
                           })
           .done(function( data, status, xhr ) {
                     if(data.hasOwnProperty("domaindialogs")) {
                         updateDomainDialogs(data.domaindialogs);
                     }
                     if(data.hasOwnProperty("domainrows")) {
                         updateDomains($("#domains"),data.domainrows);
                     }
                     if(data.hasOwnProperty("paging")) {
                         updatePaging($("#pagelist"),data.paging);
                     }
                     displayMessageJSON(data);
                     /* DEBUG: */
                     displayMessageText(JSON.stringify(data));
                     return true;
                 })
           .fail(function( xhr, status ) {
                     displayMessageText( xstatus( xhr, status, "Request" ) );
                 });
           return true;
       },
       updateCAmeta = function(tbody) {
           $(tbody).find("td.dca a[popup]")
           .each(function(idx) {
                     var capopid = $(this).attr("popup");
                     var capop   = $(capopid + " td[calink]");
                     if( capop.length == 0 ) {
                         return true;
                     }
                     var url = $(capop).attr("calink");
                     if( meta.hasOwnProperty(url) ) {
                         if( meta[url].valid ) {
                             var id = "cainfo" + meta[url].id;
                             if( $("#"+id).length == 0 ) {
                                 var txt =
"<div id=\""+id+"\" class=\"cainfo\" title=\""+$(this).text()+"\">"+
"This Certificate Authority has provided the following information about its operation.  "+
"<p>Links will open in a new window.<p><ul>";
                                 var ptxt = "";
                                 var key, ifc = 10000000;
                                 for( key in meta[url].meta ) {
                                     var tgt  = meta[url].meta[key];
                                     var desc = key;

                                     if( kmeta.hasOwnProperty(key) ) {
                                         desc = kmeta[key];
                                     }

                                     if( /^https?:\/\//.test(tgt) ) {
                                         txt += "<li><a href=\""+tgt+"\" target=\"_blank\">"+desc;
                                         txt += "</a>";
                                     } else if( /^data:(?:text\/(?:plain|html)|image\/)/.test(tgt) ) {
                                         txt += "<li><a class=\"capopclick\" popup=\"#pop" + id +
                                             "-" + ifc.toString() + "\">" + desc + "</a>";
                                         ptxt += "<div id=\"pop" + id + "-" + ifc.toString() +
                                             "\" class=\"capopup cainfo\" title=\"" +
                                             $(this).text() + " " + desc + "\">" +
                                             "<iframe sandbox=\"\" src=\"" + tgt + "\"></iframe></div>";
                                         ++ifc;
                                     } else {
                                         txt += "<li>" + desc + ": " + tgt;
                                     }
                                 }
                                 txt += "</ul>";
                                 txt += "<div class=\"caarecs\">"+
                                     "This Certificate Authority ";
                                 if( meta[url].meta.hasOwnProperty("caaIdentities")) {
                                     txt += "honors ";
                                 } else {
                                     txt += "does not honor ";
                                 }
                                 txt += "<a href=\"https://tools.ietf.org/html/rfc8659\" " +
                                        "target=\"_blank\" title=\"More information about CAA records\">" +
                                        "CAA records</a>."+
                                        "<div id=\""+id+"caa\">Inspecting configuration&hellip;</div></div>";
                                 txt += "</div>";
                                 $("#domaindialogs").append(txt).append(ptxt);
                                 activatePopups("capop");
                                 $("#"+id).dialog({modal: true,
                                                autoOpen: false,
                                               maxHeight: 0.9*$(window).innerHeight(),
                                                maxWidth: 0.9*$("body").innerWidth(),
                                                position: dposition,
                                                   width: "600px"});
                             }
                             $(capop)
                                 .removeAttr("calink")
                                 .attr("popup","#"+id)
                                 .wrapInner("<a></a>")
                                 .click(function(evt){
                                            var dlgId  = $(this).attr("popup");
                                            var dlgCaa = dlgId + "caa";
                                            var caareq = { function:"caarecs",
                                                           domain  : domain,
                                                           caurl   : url,
                                                           ids     : [] };
                                            if( meta[url].meta.hasOwnProperty("caaIdentities")) {
                                                meta[url].meta["caaIdentities"]
                                                    .forEach(function( val, att, arr) {
                                                                 this.ids.push(val);
                                                             }, caareq);
                                            }
                                            $(dlgCaa).html("Inspecting configuration&hellip;");
                                            $.ajax( window.location.pathname, {
                                                    context: $(dlgCaa),
                                                   dataType: "json",
                                                     method: "POST",
                                                contentType: "application/json",
                                                       data: JSON.stringify(caareq),
                                                    timeout: ajaxTimeout
                                                            })
                                                .done(function( data, status, xhr ) {
                                                          displayMessageJSON(data);
                                                          $(this).html(data.caarecs);
                                                          return true;
                                                      });
                                            if( !caareq.ids.length && meta[url].meta.hasOwnProperty("caaIdentities")) {
                                                $(dlgCaa).html("CA provided an empty list of CAA identities");
                                            }
                                            $(dlgId).dialog("open");
                                            return true;}
                                        );
                         }
                     } else {
                         meta[url] = {    valid: false, id: ++can };
                         var req   = { function: "getcadir",
                                       cadirurl: url };
                         $.ajax( window.location.pathname, {
                                 context: this,
                             contentType: "application/json",
                                    data: JSON.stringify(req),
                                dataType: "json",
                                  method: "POST",
                                 timeout: ajaxTimeout
                                         })
                             .done(function( data, status, xhr ) {
                                       displayMessageJSON(data);
                                       if( data.cadir.hasOwnProperty("meta") ) {
                                           meta[url].valid = true;
                                           meta[url].meta = data.cadir.meta;
                                           updateCAmeta(tbody);
                                       }
                                       return true;
                                   })
                             .fail(function( xhr, status, eThrown ) {
                                       displayMessageText( xstatus( xhr, status, "Request for " + url ) );
                                       return true;
                                   });
                     }
                     return true;
                 });
       },
       activatePopups = function(type) {
           $("." + type + "up")
           .dialog({autoOpen: false,
                       modal: true,
                   maxHeight: 0.9*$(window).innerHeight(),
                    maxWidth: 0.9*$("body").innerWidth(),
                    position: dposition,
                    minWidth: 375,
                       width: 450
                           });
          $("." + type + "click")
           .each(function(idx){
                     $(this).click(
                                   function(evt){
                                       domain = $(this).attr("domain");
                                       $($(this).attr("popup")).dialog("open");
                                       return true;});
                     return true;
                 });
           return true;
       },
       checkedChange = function() {
           var n = $("input[type='checkbox'][name=\"select\"]:checked").length;
           if( $("button[name=\"renew\"],button[name=\"revoke\"]")
               .each(function(idx) {
                         if( n ) {
                             $(this).removeClass("hidden");
                         } else {
                             $(this).addClass("hidden");
                         }
                         return true;
                     }).hasClass("hidden") ) {
               $("span.noneselected").removeClass("hidden");
           } else {
               $("span.noneselected").addClass("hidden");
           }
               return true;
       },
       updateDomains = function(tbody,data) {
          $("input[type='checkbox'][name=\"select\"]").checkboxradio("destroy");
          tbody.html(data);
          updateCAmeta(tbody);
          activatePopups( "pop" );
          makebuttons( [ { name: ["acctnewkey"],     icon: "ui-icon-refresh"},
                         { name: ["acctdeactivate"], icon: "ui-icon-trash"} ] );
          $(".dnames[hostlist]")
          .tooltip({content: function() {
                           return $($(this).attr("hostlist")).html();
                       },
                      items: "*",
                   position: { my: "left center", at: "right center",
                               collision: "flipfit" }
                   });
          $("input[type='checkbox'][name=\"select\"]")
          .checkboxradio()
          .on("click",checkedChange);
          checkedChange();
          return true;
       },
       updateDomainDialogs = function(content) {
           $(".dnames[hostlist]").tooltip("destroy");
           $(".ui-dialog-content.hostselect,"+
             ".ui-dialog-content.inspectresult,"+
             ".ui-dialog-content.cainfo,"+
             ".ui-dialog.activity").dialog("destroy").remove();
           $("#domaindialogs").html(content);
           $("select.portsel")
           .change(function() {
                       var s = "";
                       var o = $(this).prop("selectedOptions");
                       if( o.length ) {
                           for( var i = 0; i < o.length; ++i ) {
                               s = s + ", " + o[i].value.toString();
                           }
                       } else {
                           s = ", none";
                       }
                       $(this).closest("form").find("span.selected").html(s.substr(2));
                       return true;
                   });
           $("span.portsel-open")
           .click(function() {
                      $(this).closest("p").find("select.portsel")
                          .attr("size",
                                $(this)
                                .toggleClass("ui-icon-triangle-1-e ui-icon-triangle-1-s")
                                .hasClass("ui-icon-triangle-1-e")? 1: 10);
                      return true;
                  });
           $("div.hosts button.host")
           .click(function(evt) {
                      var form = $(this).closest("form.inspecthost");
                      $(form).find("input[type=\"hidden\"][name=\"host\"]").val($(this).val());
                      var postdata = $(form).serializeObject();
                      var ports    = [];
                      $(form).find("select.portsel option:selected")
                          .each(function(idx) {
                                    ports.push( { num:$(this).val(), name:$(this).text()} );
                                    return true;
                                });
                      if( ports.length < 1 ) {
                          alert( "At least one port must be selected" );
                          return false;
                      }
                      $(".inspectresult.uidialog-content").dialog("destroy").remove();
                      var div = "<div id=\"inspectresult\" class=\"inspectresult\" title=\""+postdata.host+"\">";
                      if( ports.length == 1 ) {
                          div += "<p>Inspection starting&hellip;<br>";
                      } else {
                          div += "<p>Inspections starting&hellip;<br>Each result appears in a separate tab.";
                      }
                      div += "<div id=\"inspectresulttabs\" class=\"inspectresultstab\"><ul>";
                      var p, port, pids = {};
                      for( p in ports ) {
                          port = ports[p].num;
                          pids[port] = "port" + port.toString() + "result";
                          div += "<li><a href=\"#" + pids[port] + "\">" + ports[p].name + "</a></li>";
                      }
                      div += "</ul>";
                      for( p in ports ) {
                          div += "<div id=\"" + pids[ports[p].num] + "\"></div>";
                      }
                      div += "</div></div>";
                      $(form).after(div);
                      $("#inspectresulttabs").tabs({heightStyle: "auto"});
                      $("#inspectresult")
                          .dialog({
                                  modal: true,
                              maxHeight: 0.9*$(window).innerHeight(),
                               maxWidth: 0.9*$("body").innerWidth(),
                               position: dposition,
                                  width: "min-content",
                                  close: function(ev,ui) {
                                      $(this).dialog("destroy").remove();
                                  }
                              });
                      for( p in ports ) {
                          postdata.port = ports[p].num;
                          $.ajax( window.location.pathname, {
                                  data: JSON.stringify(postdata),
                               context: $("#" + pids[ports[p].num]),
                              dataType: "json",
                                method: "POST",
                           contentType: "application/json",
                               timeout: ajaxTimeout
                                          })
                              .done(function( data, status, xhr ) {
                                        displayMessageJSON(data);
                                        if(data.hasOwnProperty("log")) {
                                            $(this)
                                                .html("<pre>"+data.log+"</pre></div>")
                                                .find(".showcert")
                                                .click(function() {
                                                           $($(this)
                                                             .toggleClass( "ui-icon-circle-plus ui-icon-circle-minus")
                                                             .attr("cert"))
                                                               .toggleClass("hidden");
                                                           return true;
                                                       });
                                        }
                                        return true;
                                    })
                              .fail(function( xhr, status ) {
                                        displayMessageText( xstatus( xhr, status, "Request for port " + ports[p].num ) );
                                        return true;
                                    });
                      }
                      return true;
                  });
           return true;
       },
       ncrumbs = 5,
       updatePaging = function( td, pars ) {
           var pagesize = parseInt($("select[name=\"pagelimit\"]").val());
           pars.start   = parseInt(pars.start) -1;
           pars.count   = parseInt(pars.count);
           pars.total   = parseInt(pars.total);
           var nav = "<ul class=\"horiz\">";
           var npgs = Math.trunc((pars.total + (pagesize -1))/pagesize);
           if( npgs <= 1 ) {
               $(td).html("");
               return true;
           }
           if( pars.start < 0 ) pars.start = 0;
           if( pars.start + pars.count > pars.total ) pars.count = pars.total - pars.start;

           var crumbspan = pagesize * ncrumbs;
           var startpg   = Math.trunc(pars.start / pagesize) * pagesize;
           var startcr   = Math.trunc(pars.start / crumbspan) * crumbspan;
           var lastpg    = Math.trunc(((pars.total -1) + (pagesize -1))/ pagesize) * pagesize;

           if( startcr >= crumbspan ) {
               nav += "<li><a value=\"" + ((startcr +1) - crumbspan).toString() + "\">&Lt;</a></li>";
           }
           var cpg, crm;
           for( crm = 0, cpg = startcr; cpg < lastpg && crm < ncrumbs; cpg += pagesize, ++crm ) {
               nav += "<li"
               if( cpg >= startpg && cpg < startpg + pagesize ) {
                   nav += " class=\"active\"";
               }
               nav += "><a value=\"" + (cpg+1).toString() + "\">" + (cpg+1).toString() + "</a></li>";
           }
           if( cpg < lastpg ) {
               nav += "<li><a value=\"" + (cpg+1).toString() + "\">&Gt;</a></li>";
           }
           nav += "</ul>";
           $(td).html(nav);
           $("tr.pagenav li:not(.active) a").click(function(evt) {
                                          return refreshCerts($(this).attr("value"));
                                      });
           return true;
       },
       maxmatch =
           $("select[name=\"pagelimit\"]")
           .change(function(evt) {
                       var first    = $("table.actions tr.pagenav li.active a").attr("value");
                       var pagesize = $(this).val();
                       maxmatch     = pagesize;
                       first        = (Math.trunc((first -1) / pagesize) * pagesize) +1;
                       return( refreshCerts(first) );
                   }).val(),
       showmore = function(li) {
           maxmatch += parseInt( $("select[name=\"pagelimit\"]").val() );
           
           return false;
       },
       refreshCerts = function(start) {
           filter   = $("#namefilter").val();
           maxmatch = parseInt( $("select[name=\"pagelimit\"]").val() );
           var req  = { function: "certformdata",
                        paging: { start: parseInt( start ),
                                  count: maxmatch,
                                 filter: filter } };
           $("#domains").html("<tr><td colspan=\"99\" class=\"comfort\">Retrieving data&hellip;</td></tr>");
           $.ajax( window.location.pathname, {
                   context: $("#certform"),
                              dataType: "json",
                                method: "POST",
                           contentType: "application/json",
                                  data: JSON.stringify( req ),
                               timeout: ajaxTimeout
                   })
           .done(function( data, status, xhr ) {
                     if(data.hasOwnProperty("domaindialogs")) {
                         updateDomainDialogs(data.domaindialogs);
                     }
                     if(data.hasOwnProperty("domainrows")) {
                         updateDomains($("#domains"),data.domainrows);
                     }
                     if(data.hasOwnProperty("paging")) {
                         updatePaging($("#pagelist"),data.paging);
                     }
                     displayMessageJSON(data);
                     return true;
                 })
           .fail(function( xhr, status ) {
                     displayMessageText( xstatus( xhr, status, "Certificates update" ) );
                 });
           return true;
       };
       $("#selectall").checkboxradio().on("click", function() {
         var setto = $(this).prop("checked");
         $("input[type='checkbox'][name=\"select\"]").each(function(idx) {
            $(this).prop("checked", setto).checkboxradio("refresh");
            return true;
           });
         return checkedChange();
      });
      makebuttons( [ { name: ["renew"],      icon: "ui-icon-refresh"},
                     { name: ["revoke"],     icon: "ui-icon-trash"},
                     { name: ["acctimport"], icon: "ui-icon-folder-open"} ] );
      $("#clearmsg").button({ icon: "ui-icon-circle-close"})
          .click(function(event) {
          $(".messages").addClass("hidden").filter("div").html("");
          return true;
              });
      var rsp;
      $("#namefilter")
          .autocomplete({
                   delay: 500,
               minLength: 5,
                  source: function(filter, respond) {
                      var req = { function: "findnames",
                                    paging: {
                                      maxmatch: maxmatch,
                                        filter: filter.term } };
                      $.ajax( window.location.pathname, {
                              context: this,
                             dataType: "json",
                               method: "POST",
                          contentType: "application/json",
                                 data: JSON.stringify( req ),
                              timeout: ajaxTimeout
                                      })
                          .done(function( data, status, xhr ) {
                                    rsp = data;
                                    if( data.hasOwnProperty("names") ) {
                                        respond(data.names);
                                    } else {
                                        respond([]);
                                    }
                                    displayMessageJSON(data);
                                    return true;
                                })
                          .fail(function( xhr, status ) {
                                    rsp = null;
                                    respond([]);
                     displayMessageText( xstatus( xhr, status, "autocomplete" ) );
                                });
                  },
                  select: function(evt, ui) {
                      if( ui.item === undefined ) {
                          setTimeout( function() {
                                          $(evt.target).autocomplete("search");
                                      }, 10 );
                          return false;
                      }
                      refreshCerts(1);
                      return true;
                  },
                  change: function(evt, ui) {
                      if( $(evt.target).val() === filter ) return true;
                      return refreshCerts(1);
                  },
                  create: function() {
                      $(this).data("ui-autocomplete")._renderMenu = function( ul, items ) {
                          var menu = this;
                          $.each( items, function( index, item ) {
                                      menu._renderItemData( ul, item );
                                  });
                          if( rsp.paging.limited ) {
                              $(ul).prepend("<li data-loadmore=\"true\" aria-label=\"Show more matches\" value=\"\"><a class=\"moreitems\" onclick=\"return showmore(this);\"> &hellip;show more matches</a></li>");
                          }
                          return $(menu);
                      };}
              })
          .closest("form").on("submit",function(evt) {
                                  evt.preventDefault();
                                  refreshCerts(1);
                                  return false;
                              });
      refreshCerts(1);
      return true;
});
