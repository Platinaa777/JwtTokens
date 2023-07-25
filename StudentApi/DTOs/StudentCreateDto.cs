using StudentApi.Models;

namespace StudentApi.DTOs;

public class StudentCreateDto
{
    public string Name { get; set; }
    public string Surname { get; set; }
    public List<LessonCreateDto> Lessons { get; set; }
}