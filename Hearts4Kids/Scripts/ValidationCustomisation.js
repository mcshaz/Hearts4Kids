﻿;$.validator.addMethod("dateITA", function (value, element) {
    var check = false,
        re = /^\d{1,2}\/\d{1,2}\/\d{4}$/,
        adata, gg, mm, aaaa, xdata;
    if (re.test(value)) {
        adata = value.split("/");
        gg = parseInt(adata[0], 10);
        mm = parseInt(adata[1], 10);
        aaaa = parseInt(adata[2], 10);
        xdata = new Date(aaaa, mm - 1, gg, 12, 0, 0, 0);
        if ((xdata.getFullYear() === aaaa) && (xdata.getMonth() === mm - 1) && (xdata.getDate() === gg)) {
            check = true;
        } else {
            check = false;
        }
    } else {
        check = false;
    }
    return this.optional(element) || check;
}, "Please enter a correct date");

$.validator.methods.date = $.validator.methods.dateITA;