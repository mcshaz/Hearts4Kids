﻿using Excel;
using Hearts4Kids.Domain;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Hearts4Kids.Services
{
    public static class GiveALittleCommunication
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="stream"></param>
        /// <returns>The number of new files added</returns>
        public static async Task<int> AddReceipts(Stream stream)
        {
            
            using (var db = new Hearts4KidsEntities())
            {
                var updatedTo = await (from r in db.Receipts
                                        where r.Id < DomainConstants.ReceiptIdentitySeed
                                        select (DateTime?)r.DateReceived).MaxAsync();
                Task<int> t = null;
                var val = new System.ComponentModel.DataAnnotations.EmailAddressAttribute();
                int count = 0;
                foreach (var gr in ExcelToReceiptList(stream).Where(rl=>rl.Date > updatedTo))
                {
                    var r = new Receipt
                    {
                        Amount = gr.Amount,
                        DateReceived = gr.Date,
                        DateSent = gr.Date,
                        Id = gr.ReceiptId,
                        TransferMethod = DomainConstants.DonationTypes.GiveALittle
                    };
                    if (val.IsValid(gr.Email))
                    {
                        if (t != null) { await t; }
                        var u = await db.AspNetUsers.FirstOrDefaultAsync(usr => usr.Email == gr.Email);
                        if (u == null)
                        {
                            var n = await db.NewsletterSubscribers.FirstOrDefaultAsync(s => s.Email == gr.Email);
                            if (n == null)
                            {
                                n = new NewsletterSubscriber
                                {
                                    Email = gr.Email,
                                    Name = gr.Name,
                                    Subscription = DomainConstants.SubscriptionTypes.FullSubscription,
                                    UnsubscribeToken = Guid.NewGuid()
                                };
                                db.NewsletterSubscribers.Add(n);
                                r.NewsletterSubscriber = n;
                            }
                            else
                            {
                                r.NewsletterSubscriber = n;
                            }
                        }
                        else
                        {
                            r.AspNetUser = u;
                        }
                        db.Receipts.Add(r);
                    }
                    else //invalid email - anonymous donation
                    {
                        db.Receipts.Add(r);
                        if (t != null)
                        {
                            await t;
                        }
                    }
#if DEBUG
                    try
                    {
#endif
                        t = db.SaveChangesAsync();
#if DEBUG
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine(ex);
                    }
#endif

                    count++;
                }
                if (t != null) { await t; }
                return count;
            }
        }

        public static IEnumerable<GiveALittleReceipt> ExcelToReceiptList(Stream stream)
        {
            using (IExcelDataReader excelReader = ExcelReaderFactory.CreateOpenXmlReader(stream))
            {
                Dictionary<string, int> columns = new Dictionary<string, int>();
                //4. DataSet - Create column names from first row
                excelReader.Read(); //1st row headers
                for (int i = 0; i< excelReader.FieldCount;i++)
                {
                    columns.Add(excelReader.GetString(i), i);
                }

                while (excelReader.Read())
                {
                    var returnVar = new GiveALittleReceipt
                    {
                        ReceiptId = excelReader.GetInt32(columns["Receipt #"]),
                        Email = excelReader.GetString(columns["Donor Email"]),
                        Name = excelReader.GetString(columns["Donor Name"]),
                        Date = excelReader.GetDateTime(columns["Date"]),
                        Amount = excelReader.GetDecimal(columns["Amount($)"]),
                    };
                    if (returnVar.ReceiptId == int.MinValue || returnVar.Date==DateTime.MinValue
                        || returnVar.Amount == default(Decimal))
                    {
                        continue;
                    }
                    yield return returnVar;
                }

            }
        }
    }

    public class GiveALittleReceipt
    {
        public int ReceiptId { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
        public DateTime Date { get; set; }
        public Decimal Amount { get; set; }
    }
}