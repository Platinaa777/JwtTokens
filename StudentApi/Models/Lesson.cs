using System.Text.Json.Serialization;

namespace StudentApi.Models;

public class Lesson
{
    public int Id { get; set; }
    public string Name { get; set; }
    public int MaxGrade { get; set; }
    [JsonIgnore]
    public List<Student> Students { get; set; }
}