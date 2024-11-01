using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace WebBanHangOnline.Models.EF
{
    [Table("tb_Category")]
    public class Category: CommonAbstract
    {
        /*Một Category sẽ có nhiều News*/
        public Category()
        {
            this.News = new HashSet<News>();
        }
        /*Tạo khóa chính*/
        [Key]
        /*Cho khóa chính tự tăng*/
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required(ErrorMessage ="Tên danh mục không được để trống")]
        [StringLength(150)]
        public string Title { get; set; }

        public string Alias { get; set; }

        /*        [StringLength(150)]
                public string TypeCode { get; set; }*/

        public string Link { get; set; }

        public string Description { get; set; }

        [StringLength(150)]
        public string SeoTitle { get; set; }

        [StringLength(250)]
        public string SeoDescription { get; set; }

        [StringLength(150)]
        public string SeoKeywords { get; set; }

        public bool IsActive { get; set; }

        public int Position { get; set; }

        /*Kết nối với khóa ngoại của bảng News*/
        public ICollection<News> News { get; set; }

        public ICollection<Posts> Posts { get; set; }
    }
}