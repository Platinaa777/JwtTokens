using System.Text.Json.Serialization;

namespace StudentApi.Models;

public class Student
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Surname { get; set; }
    public List<Lesson> Lessons { get; set; }
}