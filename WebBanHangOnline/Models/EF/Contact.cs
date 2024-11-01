using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace WebBanHangOnline.Models.EF
{
    [Table("tb_Contact")]
    public class Contact:CommonAbstract
    {
        /*Tạo khóa chính*/
        [Key]
        /*Cho khóa chính tự tăng*/
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        /*Tạo cho giá trị của một trường NOT NULL*/
        [Required(ErrorMessage = "Tên không được để trống")]
        /*Quy định độ dài*/
        [StringLength(150,ErrorMessage ="Không được vượt quá 150 ký tự")]
        public string Name { get; set; }

        /*Quy định độ dài*/
        [StringLength(150, ErrorMessage = "Không được vượt quá 150 ký tự")]
        public string Email { get; set; }

        public string Website { get; set; }

        /*Quy định độ dài*/
        [StringLength(4000)]
        public string Message { get; set; }

        public bool isRead { get; set; }
    }
}