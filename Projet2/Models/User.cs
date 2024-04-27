using System.ComponentModel.DataAnnotations;

namespace Projet2.Models
{
    public class User
    {
        public int userID { get; set; }

        [Required(ErrorMessage = "The Name field is required.")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "The Name must be between 3 and 50 characters.")]
        public string? name { get; set; }

        [Required(ErrorMessage = "The Email field is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address.")]
        public string? email { get; set; }

        [Required(ErrorMessage = "The Password field is required.")]
        [StringLength(20, MinimumLength = 6, ErrorMessage = "The Password must be between 6 and 20 characters.")]
        public string? password { get; set; }
    }
}
