namespace RentaVehiculosAPI.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using RentaVehiculosAPI.Data;
    using RentaVehiculosAPI.Models;

    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class VehiculosController : ControllerBase
    {
        private readonly AppDbContext _context;

        public VehiculosController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult GetVehiculos()
        {
            var vehiculos = _context.Vehiculos.ToList();
            return Ok(vehiculos);
        }

        [HttpGet("{id}")]
        public IActionResult GetVehiculo(int id)
        {
            var vehiculo = _context.Vehiculos.Find(id);
            if (vehiculo == null) return NotFound();
            return Ok(vehiculo);
        }

        [HttpPost]
        public IActionResult CreateVehiculo([FromBody] Vehiculo vehiculo)
        {
            _context.Vehiculos.Add(vehiculo);
            _context.SaveChanges();
            return CreatedAtAction(nameof(GetVehiculo), new { id = vehiculo.ID }, vehiculo);
        }

        [HttpPut("{id}")]
        public IActionResult UpdateVehiculo(int id, [FromBody] Vehiculo vehiculo)
        {
            var existingVehiculo = _context.Vehiculos.Find(id);
            if (existingVehiculo == null) return NotFound();

            existingVehiculo.Marca = vehiculo.Marca;
            existingVehiculo.Modelo = vehiculo.Modelo;
            existingVehiculo.Año = vehiculo.Año;
            existingVehiculo.Estado = vehiculo.Estado;
            existingVehiculo.TarifaPorHora = vehiculo.TarifaPorHora;
            existingVehiculo.PenalizacionPorHora = vehiculo.PenalizacionPorHora;

            _context.SaveChanges();
            return NoContent();
        }

        [HttpDelete("{id}")]
        public IActionResult DeleteVehiculo(int id)
        {
            var vehiculo = _context.Vehiculos.Find(id);
            if (vehiculo == null) return NotFound();

            _context.Vehiculos.Remove(vehiculo);
            _context.SaveChanges();
            return NoContent();
        }
    }

}
